//! THE argv layout (issue #6) — every element in emission order. This
//! module is the golden contract: any change here must be a deliberate,
//! reviewed edit that updates the goldens and the proptest invariants in
//! the tests below (they are intentionally brittle).
//!
//! ```text
//!  1  {bwrap_path}                                 ← absolute, verbatim
//!  2  --unshare-user --unshare-pid --unshare-ipc --unshare-uts
//!     --unshare-cgroup-try                        ← never --unshare-net
//!  3  --disable-userns --cap-drop ALL --die-with-parent --new-session
//!     --hostname sandbox
//!  4  --clearenv
//!  5  --symlink usr/bin /bin      ┐ the four usr-merge shims, in this
//!     --symlink usr/sbin /sbin    │ fixed order, each SKIPPED when its
//!     --symlink usr/lib /lib      │ dest (/bin, /sbin, /lib, /lib64) is
//!     --symlink usr/lib64 /lib64  ┘ any bind's dest OR any deny path
//!  6  the merged mount list, sorted by (dest ascending BYTE order, prio
//!     ascending), deduped on exact (op, src, dest) keeping max prio;
//!     each emits {--ro-bind|--bind} {src} {dest}:
//!       prio 0 — policy filesystem.ro (list order) and .rw (list order)
//!       prio 1 — infra /etc set (plain binds, src == dest, Q1/Q9)
//!       prio 1 — generated files (src from SessionLayout):
//!                <session>/etc/resolv.conf → /etc/resolv.conf
//!                <session>/etc/passwd      → /etc/passwd
//!                <session>/etc/group       → /etc/group
//!       prio 2 — session leaves (rw): work → /work, home → /root,
//!                tmp → /tmp
//!  7  --proc /proc --dev /dev                      ← fixed, after ALL binds
//!  8  --tmpfs {deny} for each policy deny path, sorted dest-ascending
//!     byte order, deduped — always last among filesystem ops (Q5)
//!  9  --setenv HOME /root, PATH {INFRA_PATH}, TMPDIR /tmp — the infra
//!     trio, alphabetical (Q3/Q7)
//! 10  --setenv {name} {value} for passed_env entries whose name is in
//!     policy.env.pass, in BTreeMap (sorted-name) order — the membership
//!     FILTER is deliberate (Q11 seam)
//! 11  --setenv {k} {v} for policy.env.set in BTreeMap order (overrides
//!     pass on name collision — emission order = precedence)
//! 12  explicit mode ONLY (Q4): the 8 proxy vars in a FIXED order —
//!     ALL_PROXY, HTTP_PROXY, HTTPS_PROXY, NO_PROXY + lowercase twins
//!     (not byte order: HTTPS_PROXY would sort before HTTP_PROXY);
//!     values from init::consts::{EXPLICIT_TCP_PORT, SANDBOX_ADDR}
//! 13  --chdir {cwd | /work}
//! 14  --
//! 15  the command elements verbatim (byte-preserving OsString copies)
//! ```
//!
//! Sort/dedup semantics (module docs point 4): byte order on dest IS the
//! ancestors-first rule ("/etc" < "/etc/ssl" < "/tmp" < "/tmp/x" < "/usr");
//! prio ascending + bwrap's sequential last-mount-wins IS the
//! infra/session-win collision rule (Q13) — same-dest different-src entries
//! are BOTH emitted, prio-ordered, so the higher-prio source mounts last
//! and wins. There is no collision error class by design (golden 4 pins
//! the behavior).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use super::Build;
use super::etc::{DEST_HOME, DEST_TMP, DEST_WORK, SessionLayout, session_layout};
use crate::init::consts::{EXPLICIT_TCP_PORT, SANDBOX_ADDR};
use crate::policy::{AbsolutePath, NetworkMode};

/// The infra `PATH` (Q3): the standard sbin/bin search path so payload
/// tooling resolves without policy involvement. Emitted in the infra
/// block BEFORE pass/set, so policy can override it (last --setenv wins).
const INFRA_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The mandatory infra `/etc` binds (Q1): toolchain prerequisites with no
/// secrets — always bound as infrastructure regardless of policy (the
/// policy states the MINIMUM). Plain ro binds, src == dest, deliberately
/// fail-closed: no `-try` variants, so a host missing any of these aborts
/// bwrap and the sandbox never starts (Q9; #11 pre-detects and reports).
/// Declaration order is dest-sorted; emission order comes from the merge
/// sort anyway.
const INFRA_ETC: [&str; 7] = [
    "/etc/alternatives",
    "/etc/ca-certificates",
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/ssl",
];

/// The four usr-merge shims (module docs point 8): (dest, relative
/// target). Fixed order; the skip rule applies at emission time — a
/// mount/--tmpfs on a symlink FOLLOWS the link, so a shim whose dest is a
/// bind dest or a deny path would silently redirect that op onto /usr/*.
const USR_MERGE_SHIMS: [(&str, &str); 4] = [
    ("/bin", "usr/bin"),
    ("/sbin", "usr/sbin"),
    ("/lib", "usr/lib"),
    ("/lib64", "usr/lib64"),
];

// Mount priority classes (module docs point 4): ascending, and bwrap's
// last-mount-wins makes the higher-prio op win same-dest collisions (Q13).
const PRIO_POLICY: u8 = 0;
const PRIO_INFRA: u8 = 1;
const PRIO_SESSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindOp {
    Ro,
    Rw,
}

impl BindOp {
    fn flag(self) -> &'static str {
        match self {
            BindOp::Ro => "--ro-bind",
            BindOp::Rw => "--bind",
        }
    }
}

#[derive(Debug)]
struct Mount {
    op: BindOp,
    src: PathBuf,
    dest: String,
    prio: u8,
}

/// Assemble the complete argv — infallible: [`super::build`] validated
/// every input first (module docs point 2), and the layout itself has no
/// failure modes. Deterministic: identical inputs ⇒ byte-identical argv
/// (proptest P6).
pub(super) fn assemble(input: &Build<'_>) -> Vec<OsString> {
    let layout = session_layout(input.session_dir);
    let mut argv: Vec<OsString> = Vec::new();

    // 1. argv[0]: the absolute bwrap path, verbatim (R16 — __init's
    //    execvp has no PATH to search).
    argv.push(input.bwrap_path.as_os_str().to_os_string());

    // 2. The unshare block — NEVER --unshare-net (module docs point 6):
    //    the netns belongs to sbx __init (#5); bwrap joins the inherited
    //    one, where the nftables rules and listeners already live.
    for flag in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ] {
        argv.push(OsString::from(flag));
    }

    // 3. The hardening block (module docs point 7). --disable-userns
    //    requires --unshare-user (present above) and bwrap >= 0.8
    //    (version::BWRAP_MIN); --hostname requires --unshare-uts
    //    (present).
    for flag in [
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "sandbox",
    ] {
        argv.push(OsString::from(flag));
    }

    // 4. The environment is built exclusively from the explicit --setenv
    //    emissions below (module docs point 5).
    argv.push(OsString::from("--clearenv"));

    // The merged mount list (element 6) — computed before the shims
    // because the shim skip rule needs the bind-dest set.
    let mounts = merged_mounts(input, &layout);
    let bind_dests: BTreeSet<&str> = mounts.iter().map(|mount| mount.dest.as_str()).collect();
    let denies = sorted_denies(&input.policy.filesystem.deny);

    // 5. The usr-merge shims (module docs point 8), each skipped when its
    //    dest is a bind dest OR a deny path.
    for (dest, target) in USR_MERGE_SHIMS {
        if bind_dests.contains(dest) || denies.contains(&dest) {
            continue;
        }
        argv.extend(["--symlink", target, dest].map(OsString::from));
    }

    // 6. The binds, in merged order (dest byte-ascending, prio ascending).
    for mount in &mounts {
        argv.push(OsString::from(mount.op.flag()));
        argv.push(mount.src.as_os_str().to_os_string());
        argv.push(OsString::from(&mount.dest));
    }

    // 7. A fresh /proc and /dev after ALL binds — never the host /proc
    //    (module docs points 4/7). Any policy bind under /proc or /dev is
    //    silently covered by this (documented limitation; proptest P7
    //    pins the position).
    argv.extend(["--proc", "/proc", "--dev", "/dev"].map(OsString::from));

    // 8. Deny masks LAST among the filesystem ops — deny always wins
    //    (Q5). Sorted dest-ascending byte order, deduped.
    for deny in &denies {
        argv.push(OsString::from("--tmpfs"));
        argv.push(OsString::from(deny));
    }

    // 9. The infra env trio, alphabetical (Q3/Q7): HOME matches the
    //    synthetic passwd (uid 0 ⇒ /root), TMPDIR the session tmp leaf.
    //    Later groups override these by name (last --setenv wins): policy
    //    CAN override PATH/HOME; the proxy vars below are NOT
    //    policy-overridable in explicit mode (infra decides, module docs
    //    point 5).
    setenv(&mut argv, "HOME", OsStr::new(DEST_HOME));
    setenv(&mut argv, "PATH", OsStr::new(INFRA_PATH));
    setenv(&mut argv, "TMPDIR", OsStr::new(DEST_TMP));

    // 10. The resolved env.pass values (Q11 seam): the membership FILTER
    //     is deliberate — a buggy resolver can never inject a name the
    //     policy did not allow. BTreeMap iteration = sorted-name order.
    //     Non-POSIX passed_env keys need no separate check: a key is
    //     emitted only by being a pass name, and pass names are
    //     POSIX-validated at the deserialize level (the policy validity
    //     invariant — see the policy module doc point 5's residual
    //     struct-literal gap), hence NUL-free.
    for (name, value) in input.passed_env {
        if input.policy.env.pass.iter().any(|allowed| allowed == name) {
            setenv(&mut argv, name, value);
        }
    }

    // 11. env.set in BTreeMap order; overrides pass on a name collision
    //     (emission order = precedence, documented).
    for (name, value) in &input.policy.env.set {
        setenv(&mut argv, name, OsStr::new(value));
    }

    // 12. The explicit-mode proxy vars (Q4: BOTH cases — 8 vars, fixed
    //     order: ALL/HTTP/HTTPS/NO uppercase, then the lowercase twins;
    //     NOT byte order — strict byte order would put HTTPS_PROXY before
    //     HTTP_PROXY, 'S' < '_'). Values are formatted
    //     from init::consts — the single source whose docs already
    //     forward-reference #6. Emitted LAST, so they override any
    //     same-named env.set (infra decides; golden 6 pins it).
    if input.policy.network.mode == NetworkMode::Explicit {
        let proxy = format!("http://127.0.0.1:{EXPLICIT_TCP_PORT}");
        let no_proxy = format!("localhost,127.0.0.1,{SANDBOX_ADDR}");
        for (name, value) in [
            ("ALL_PROXY", &proxy),
            ("HTTP_PROXY", &proxy),
            ("HTTPS_PROXY", &proxy),
            ("NO_PROXY", &no_proxy),
            ("all_proxy", &proxy),
            ("http_proxy", &proxy),
            ("https_proxy", &proxy),
            ("no_proxy", &no_proxy),
        ] {
            setenv(&mut argv, name, OsStr::new(value));
        }
    }

    // 13. The working directory inside the sandbox (the cli.rs --cwd
    //     contract: sandbox-side; default is the session work leaf).
    argv.push(OsString::from("--chdir"));
    match input.cwd {
        Some(cwd) => argv.push(cwd.as_os_str().to_os_string()),
        None => argv.push(OsString::from(DEST_WORK)),
    }

    // 14–15. The command VERBATIM after `--` (Q12: no shell wrapping —
    //        that is #10's decision; byte-preserving OsString copies).
    argv.push(OsString::from("--"));
    argv.extend(input.command.iter().cloned());

    argv
}

fn setenv(argv: &mut Vec<OsString>, name: &str, value: &OsStr) {
    argv.push(OsString::from("--setenv"));
    argv.push(OsString::from(name));
    argv.push(value.to_os_string());
}

/// The merged, deduped, sorted mount list (module docs point 4; layout
/// element 6).
fn merged_mounts(input: &Build<'_>, layout: &SessionLayout) -> Vec<Mount> {
    let mut mounts = Vec::new();

    // Prio 0 — the policy lists in written order (ro, then rw). Src ==
    // dest == the written path: zero normalization (the policy
    // AbsolutePath contract — stored string == what bwrap sees).
    for path in &input.policy.filesystem.ro {
        mounts.push(policy_mount(BindOp::Ro, path));
    }
    for path in &input.policy.filesystem.rw {
        mounts.push(policy_mount(BindOp::Rw, path));
    }

    // Prio 1 — the infra /etc set: plain ro binds, src == dest (Q1/Q9).
    for dest in INFRA_ETC {
        mounts.push(Mount {
            op: BindOp::Ro,
            src: PathBuf::from(dest),
            dest: dest.to_owned(),
            prio: PRIO_INFRA,
        });
    }

    // Prio 1 — the generated synthetic files (Q6): individually bound
    // from the session dir (no fd-passing — #5's fd_hygiene closes every
    // fd > 2 before exec, so --ro-bind-data is impossible).
    for (src, dest) in [
        (&layout.resolv_conf, "/etc/resolv.conf"),
        (&layout.passwd, "/etc/passwd"),
        (&layout.group, "/etc/group"),
    ] {
        mounts.push(Mount {
            op: BindOp::Ro,
            src: src.clone(),
            dest: dest.to_owned(),
            prio: PRIO_INFRA,
        });
    }

    // Prio 2 — the three session leaves, rw (Q7): ONLY the leaves; the
    // session dir itself and its parent are never bound (module docs
    // point 3).
    for (src, dest) in [
        (&layout.work, DEST_WORK),
        (&layout.home, DEST_HOME),
        (&layout.tmp, DEST_TMP),
    ] {
        mounts.push(Mount {
            op: BindOp::Rw,
            src: src.clone(),
            dest: dest.to_owned(),
            prio: PRIO_SESSION,
        });
    }

    // Exact (op, src, dest) duplicates collapse, keeping the MAX prio: a
    // policy duplicate of an infra op emits once at infra prio (golden
    // 1's /etc/ssl). Seen-map keyed by the byte-ordered tuple; the
    // emission order comes from the sort below, so the map's own order is
    // irrelevant and the first occurrence's POSITION only matters for
    // same-(dest, prio) ties — collection order (policy ro → policy rw →
    // infra → generated → session), fixed and deterministic.
    let mut seen: BTreeMap<(&'static str, PathBuf, String), usize> = BTreeMap::new();
    let mut deduped: Vec<Mount> = Vec::with_capacity(mounts.len());
    for mount in mounts {
        let key = (mount.op.flag(), mount.src.clone(), mount.dest.clone());
        match seen.get(&key) {
            Some(&index) => {
                let kept = &mut deduped[index];
                kept.prio = kept.prio.max(mount.prio);
            }
            None => {
                seen.insert(key, deduped.len());
                deduped.push(mount);
            }
        }
    }

    // THE single sort: (dest ascending byte order, prio ascending),
    // STABLE — byte order on dest is exactly the ancestors-first rule
    // ("/etc" < "/etc/ssl" < "/tmp" < "/tmp/x" < "/usr"), and prio +
    // bwrap's last-mount-wins is the infra/session-win rule (Q13).
    deduped.sort_by(|a, b| {
        a.dest
            .as_bytes()
            .cmp(b.dest.as_bytes())
            .then(a.prio.cmp(&b.prio))
    });
    deduped
}

fn policy_mount(op: BindOp, path: &AbsolutePath) -> Mount {
    Mount {
        op,
        src: path.as_path().to_path_buf(),
        dest: path.as_str().to_owned(),
        prio: PRIO_POLICY,
    }
}

/// The deny paths sorted dest-ascending byte order, deduped (Q5) — &str's
/// Ord IS byte order. Policy validation does not reject duplicates within
/// a list; identical --tmpfs masks would be harmless but noisy, so they
/// collapse.
fn sorted_denies(deny: &[AbsolutePath]) -> Vec<&str> {
    let mut paths: Vec<&str> = deny.iter().map(AbsolutePath::as_str).collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bwrap::build;
    use crate::policy::Policy;
    use proptest::prelude::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    // ---- golden fixtures (design §2.6) --------------------------------------
    //
    // Policies are constructed via JSON fixtures through the real pipeline
    // (from_json_str/from_file) — never struct literals (there is no
    // public constructor; this exercises the validated path). Fixed golden
    // inputs: session dir, bwrap path, command, cwd as noted. Goldens are
    // intentionally brittle: any layout change must be a deliberate,
    // reviewed edit that updates them.

    const SESSION_DIR: &str = "/tmp/sbx-golden-session";
    const BWRAP: &str = "/usr/bin/bwrap";

    /// The crafted-golden base fixture (draft shape, empty lists,
    /// transparent mode) — each golden replaces exactly what it pins (the
    /// policy.rs DRAFT/draft_with precedent).
    const BASE: &str = r#"{
      "version": 1,
      "filesystem": { "ro": [], "rw": [], "deny": [] },
      "network": { "mode": "transparent", "allow": [], "ports": [] },
      "env": { "pass": [], "set": {} },
      "limits": { "timeout": "120s", "output_bytes": 10485760 }
    }"#;

    /// Apply `(from, to)` replacements to [`BASE`] in order; panics if a
    /// `from` is missing (a silent no-op would make goldens vacuous).
    fn base_with(replacements: &[(&str, &str)]) -> String {
        let mut json = BASE.to_owned();
        for (from, to) in replacements {
            assert!(json.contains(from), "fixture lacks {from:?}");
            json = json.replace(from, to);
        }
        json
    }

    fn policy_of(json: &str) -> Policy {
        Policy::from_json_str(json).unwrap_or_else(|err| panic!("fixture must parse: {err}"))
    }

    fn example(name: &str) -> Policy {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(name);
        Policy::from_file(&path).unwrap_or_else(|err| panic!("{name} must parse: {err}"))
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn env_map(entries: &[(&str, &str)]) -> BTreeMap<String, OsString> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
            .collect()
    }

    /// Build with the fixed golden inputs (cwd `None`, command
    /// `/bin/echo hi`) and return the argv.
    fn golden_argv(policy: &Policy, passed_env: &BTreeMap<String, OsString>) -> Vec<OsString> {
        golden_argv_full(policy, passed_env, None, &os(&["/bin/echo", "hi"]))
    }

    fn golden_argv_full(
        policy: &Policy,
        passed_env: &BTreeMap<String, OsString>,
        cwd: Option<&Path>,
        command: &[OsString],
    ) -> Vec<OsString> {
        let input = Build {
            policy,
            session_dir: Path::new(SESSION_DIR),
            bwrap_path: Path::new(BWRAP),
            command,
            cwd,
            passed_env,
        };
        build(&input)
            .expect("golden inputs must build")
            .argv()
            .to_vec()
    }

    // Shared expected-argv blocks. Deliberately spelled out (not computed
    // from the production constants): a drift between these literals and
    // INFRA_ETC/USR_MERGE_SHIMS/INFRA_PATH is exactly what a golden must
    // catch.

    /// Elements 1–4: bwrap path + unshare block + hardening block +
    /// --clearenv.
    const HEAD: &[&str] = &[
        "/usr/bin/bwrap",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "sandbox",
        "--clearenv",
    ];

    /// Element 5 with all four shims emitted.
    const SHIMS: &[&str] = &[
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
    ];

    /// Element 6, infra half (no policy binds): the infra /etc set with
    /// the three generated files interleaved in dest byte order.
    const INFRA_BINDS_NO_POLICY: &[&str] = &[
        "--ro-bind",
        "/etc/alternatives",
        "/etc/alternatives",
        "--ro-bind",
        "/etc/ca-certificates",
        "/etc/ca-certificates",
        "--ro-bind",
        "/tmp/sbx-golden-session/etc/group",
        "/etc/group",
        "--ro-bind",
        "/etc/hosts",
        "/etc/hosts",
        "--ro-bind",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind",
        "/etc/localtime",
        "/etc/localtime",
        "--ro-bind",
        "/etc/nsswitch.conf",
        "/etc/nsswitch.conf",
        "--ro-bind",
        "/tmp/sbx-golden-session/etc/passwd",
        "/etc/passwd",
        "--ro-bind",
        "/tmp/sbx-golden-session/etc/resolv.conf",
        "/etc/resolv.conf",
        "--ro-bind",
        "/etc/ssl",
        "/etc/ssl",
    ];

    /// Element 6, session half: home → /root and tmp → /tmp (work sorts
    /// after every "/u*" dest, so it is pinned separately).
    const SESSION_BINDS: &[&str] = &[
        "--bind",
        "/tmp/sbx-golden-session/home",
        "/root",
        "--bind",
        "/tmp/sbx-golden-session/tmp",
        "/tmp",
    ];
    const WORK_BIND: &[&str] = &["--bind", "/tmp/sbx-golden-session/work", "/work"];

    /// Element 7.
    const PROC_DEV: &[&str] = &["--proc", "/proc", "--dev", "/dev"];

    /// Element 9.
    const INFRA_ENV: &[&str] = &[
        "--setenv",
        "HOME",
        "/root",
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv",
        "TMPDIR",
        "/tmp",
    ];

    /// Elements 13–15 with the default cwd and the golden command.
    const TAIL: &[&str] = &["--chdir", "/work", "--", "/bin/echo", "hi"];

    fn expected(parts: &[&[&str]]) -> Vec<OsString> {
        parts
            .iter()
            .flat_map(|part| part.iter())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn golden_default_example_argv() {
        // Golden 1: the shipped default example, FULL argv byte-exact.
        // The policy's /etc/ssl ro bind dedups into the infra entry
        // (Q1/Q13); transparent mode ⇒ no proxy vars; LANG passes the
        // membership filter; GIT_TERMINAL_PROMPT comes from env.set.
        let policy = example("default.json");
        let argv = golden_argv(&policy, &env_map(&[("LANG", "C.UTF-8")]));
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                &["--ro-bind", "/usr", "/usr"],
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                &["--setenv", "LANG", "C.UTF-8"],
                &["--setenv", "GIT_TERMINAL_PROMPT", "0"],
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_locked_down_example_argv() {
        // Golden 2: the shipped locked-down example with an empty
        // passed_env — infra-only binds, mode none ⇒ no proxy vars, no
        // pass/set lines. The minimal complete argv.
        let policy = example("locked-down.json");
        let argv = golden_argv(&policy, &BTreeMap::new());
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_nesting_order() {
        // Golden 3: nested ro/rw is legal (Q8) and the dest byte-order
        // sort IS the ancestors-first rule: /usr → /usr/share →
        // /usr/share/doc, the ro parent before the nested rw.
        let policy = policy_of(&base_with(&[(
            r#""ro": [], "rw": []"#,
            r#""ro": ["/usr", "/usr/share"], "rw": ["/usr/share/doc"]"#,
        )]));
        let argv = golden_argv(&policy, &BTreeMap::new());
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                &[
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--ro-bind",
                    "/usr/share",
                    "/usr/share",
                    "--bind",
                    "/usr/share/doc",
                    "/usr/share/doc",
                ],
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_collision_infra_wins() {
        // Golden 4 (Q13): same-dest collisions resolved by priority +
        // bwrap's last-mount-wins — no error class. The policy
        // /etc/hosts collapses into the infra entry (exact duplicate);
        // the policy /etc/passwd emits BEFORE the generated bind (prio
        // 0 < 1 ⇒ generated wins); the policy ro /tmp before the session
        // rw /tmp (session wins).
        let policy = policy_of(&base_with(&[(
            r#""ro": []"#,
            r#""ro": ["/etc/hosts", "/tmp", "/etc/passwd"]"#,
        )]));
        let argv = golden_argv(&policy, &BTreeMap::new());
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                &[
                    "--ro-bind",
                    "/etc/alternatives",
                    "/etc/alternatives",
                    "--ro-bind",
                    "/etc/ca-certificates",
                    "/etc/ca-certificates",
                    "--ro-bind",
                    "/tmp/sbx-golden-session/etc/group",
                    "/etc/group",
                    "--ro-bind",
                    "/etc/hosts",
                    "/etc/hosts",
                    "--ro-bind",
                    "/etc/ld.so.cache",
                    "/etc/ld.so.cache",
                    "--ro-bind",
                    "/etc/localtime",
                    "/etc/localtime",
                    "--ro-bind",
                    "/etc/nsswitch.conf",
                    "/etc/nsswitch.conf",
                    "--ro-bind",
                    "/etc/passwd",
                    "/etc/passwd",
                    "--ro-bind",
                    "/tmp/sbx-golden-session/etc/passwd",
                    "/etc/passwd",
                    "--ro-bind",
                    "/tmp/sbx-golden-session/etc/resolv.conf",
                    "/etc/resolv.conf",
                    "--ro-bind",
                    "/etc/ssl",
                    "/etc/ssl",
                    "--bind",
                    "/tmp/sbx-golden-session/home",
                    "/root",
                    "--ro-bind",
                    "/tmp",
                    "/tmp",
                    "--bind",
                    "/tmp/sbx-golden-session/tmp",
                    "/tmp",
                    "--bind",
                    "/tmp/sbx-golden-session/work",
                    "/work",
                ],
                PROC_DEV,
                INFRA_ENV,
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_deny_last_and_symlink_skip() {
        // Golden 5 (Q5 + module docs point 8): the deny --tmpfs masks
        // sort dest-ascending and come LAST among the filesystem ops
        // (deny wins over everything); AND the /bin deny suppresses the
        // --symlink usr/bin /bin shim — a --tmpfs on a symlink would
        // follow it onto /usr/bin. The other three shims stay.
        let policy = policy_of(&base_with(&[(
            r#""ro": [], "rw": [], "deny": []"#,
            r#""ro": ["/usr"], "rw": [], "deny": ["/usr/share/doc", "/bin"]"#,
        )]));
        let argv = golden_argv(&policy, &BTreeMap::new());
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                &[
                    "--symlink",
                    "usr/sbin",
                    "/sbin",
                    "--symlink",
                    "usr/lib",
                    "/lib",
                    "--symlink",
                    "usr/lib64",
                    "/lib64",
                ],
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                &["--ro-bind", "/usr", "/usr"],
                WORK_BIND,
                PROC_DEV,
                &["--tmpfs", "/bin", "--tmpfs", "/usr/share/doc"],
                INFRA_ENV,
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_explicit_proxy_env() {
        // Golden 6 (Q4): explicit mode ⇒ the 8 proxy vars in the fixed
        // emission order (ALL/HTTP/HTTPS/NO uppercase, then the lowercase
        // twins — NOT byte order) with the consts-derived
        // values — emitted AFTER env.set, so a policy-set HTTP_PROXY is
        // overridden (infra decides; module docs point 5).
        let policy = policy_of(&base_with(&[
            (r#""mode": "transparent""#, r#""mode": "explicit""#),
            (r#""set": {}"#, r#""set": { "HTTP_PROXY": "attacker" }"#),
        ]));
        let argv = golden_argv(&policy, &BTreeMap::new());
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                &["--setenv", "HTTP_PROXY", "attacker"],
                &[
                    "--setenv",
                    "ALL_PROXY",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "HTTP_PROXY",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "HTTPS_PROXY",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "NO_PROXY",
                    "localhost,127.0.0.1,10.255.255.1",
                    "--setenv",
                    "all_proxy",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "http_proxy",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "https_proxy",
                    "http://127.0.0.1:3128",
                    "--setenv",
                    "no_proxy",
                    "localhost,127.0.0.1,10.255.255.1",
                ],
                TAIL,
            ])
        );
    }

    #[test]
    fn golden_non_utf8_command() {
        // Golden 7: Linux argv is arbitrary bytes — the verbatim contract
        // (cli.rs's OsString trailing arg) survives the builder: the tail
        // bytes are preserved EXACTLY after `--`, invalid UTF-8 included.
        let policy = policy_of(BASE);
        let command = vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from_vec(b"echo \xff\xfe".to_vec()),
        ];
        let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
        let mut want = expected(&[
            HEAD,
            SHIMS,
            INFRA_BINDS_NO_POLICY,
            SESSION_BINDS,
            WORK_BIND,
            PROC_DEV,
            INFRA_ENV,
            &["--chdir", "/work", "--", "/bin/sh", "-c"],
        ]);
        want.push(OsString::from_vec(b"echo \xff\xfe".to_vec()));
        assert_eq!(argv, want);
        // Byte-level pin of the non-UTF-8 element itself.
        assert_eq!(
            argv[argv.len() - 1].as_os_str().as_bytes(),
            b"echo \xff\xfe"
        );
    }

    #[test]
    fn golden_cwd_override() {
        // Golden 8: a sandbox-side cwd (the cli.rs --cwd contract)
        // overrides the /work default; everything else is golden 2's
        // argv.
        let policy = example("locked-down.json");
        let argv = golden_argv_full(
            &policy,
            &BTreeMap::new(),
            Some(Path::new("/work/sub")),
            &os(&["/bin/echo", "hi"]),
        );
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                &["--chdir", "/work/sub", "--", "/bin/echo", "hi"],
            ])
        );
    }

    #[test]
    fn golden_pass_filter() {
        // Golden 9 (Q11 seam): passed_env emits ONLY through the
        // policy.env.pass membership filter — a buggy resolver passing
        // EVIL can never inject it.
        let policy = policy_of(&base_with(&[(r#""pass": []"#, r#""pass": ["LANG"]"#)]));
        let argv = golden_argv(&policy, &env_map(&[("LANG", "C"), ("EVIL", "x")]));
        assert_eq!(
            argv,
            expected(&[
                HEAD,
                SHIMS,
                INFRA_BINDS_NO_POLICY,
                SESSION_BINDS,
                WORK_BIND,
                PROC_DEV,
                INFRA_ENV,
                &["--setenv", "LANG", "C"],
                TAIL,
            ])
        );
    }

    // ---- proptest invariants P1–P9 (design §2.6) -----------------------------
    //
    // House style from egress.rs: core strategies only (proptest 1.11 has
    // no char_in; char::range + Just + collection::* fully define the
    // output sets). The generators emit only VALID policies — asserted by
    // from_json_str in prop_policy, so generator drift fails loudly
    // instead of silently vacuating the properties. Deep runs:
    // PROPTEST_CASES=10000 cargo test --locked bwrap::argv (the default —
    // and CI — runs 256 cases per property).
    //
    // Every case builds with the fixed golden inputs (SESSION_DIR, BWRAP,
    // cwd None) plus an arbitrary NUL-free byte command (the cli.rs
    // verbatim contract's adversarial half).

    fn prop_policy(json: &str) -> Policy {
        policy_of(json)
    }

    // path segment: [a-z0-9]{1,8} — never "."/"..", so every generated
    // path is lexically canonical (check_path) and NUL-free.
    fn prop_segment() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop_lower_alnum_char(), 1..=8)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn prop_lower_alnum_char() -> impl Strategy<Value = char> {
        prop_oneof![
            proptest::char::range('a', 'z'),
            proptest::char::range('0', '9'),
        ]
    }

    // absolute path: 1–3 segments.
    fn prop_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop_segment(), 1..=3)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    // POSIX env name: [A-Za-z_][A-Za-z0-9_]{0,7}.
    fn prop_env_name() -> impl Strategy<Value = String> {
        (
            prop_oneof![
                proptest::char::range('A', 'Z'),
                proptest::char::range('a', 'z'),
                proptest::strategy::Just('_'),
            ],
            proptest::collection::vec(prop_env_name_char(), 0..=7),
        )
            .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
    }

    fn prop_env_name_char() -> impl Strategy<Value = char> {
        prop_oneof![
            proptest::char::range('A', 'Z'),
            proptest::char::range('a', 'z'),
            proptest::char::range('0', '9'),
            proptest::strategy::Just('_'),
        ]
    }

    // env value: arbitrary chars minus NUL (policy leaves values
    // unrestricted; NUL is build() row 9's rejection, so generators must
    // not emit it).
    fn prop_env_value() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            proptest::char::any().prop_filter("NUL is rejected by build() row 9", |c| *c != '\0'),
            0..=8,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    // command: 1–4 elements of 1–12 arbitrary bytes, NUL-free (row 8).
    fn prop_command() -> impl Strategy<Value = Vec<OsString>> {
        proptest::collection::vec(
            proptest::collection::vec(
                proptest::num::u8::ANY.prop_filter("NUL is rejected by build() row 8", |b| *b != 0),
                1..=12,
            ),
            1..=4,
        )
        .prop_map(|elements| elements.into_iter().map(OsString::from_vec).collect())
    }

    fn prop_passed_env() -> impl Strategy<Value = BTreeMap<String, OsString>> {
        proptest::collection::btree_map(prop_env_name(), prop_env_value(), 0..=4).prop_map(
            |entries| {
                entries
                    .into_iter()
                    .map(|(name, value)| (name, OsString::from(value)))
                    .collect()
            },
        )
    }

    // A valid policy JSON text generator: version 1, three modes, ports
    // 1..=65535, and the Q8 fixup — rw members exactly equal to a ro
    // member are dropped (deterministic, not sample rejection; nesting in
    // either direction stays, which is what P1 exercises).
    fn prop_policy_json() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(prop_path(), 0..=4),
            proptest::collection::vec(prop_path(), 0..=4),
            proptest::collection::vec(prop_path(), 0..=3),
            prop_oneof![
                proptest::strategy::Just("transparent"),
                proptest::strategy::Just("explicit"),
                proptest::strategy::Just("none"),
            ],
            proptest::collection::vec(prop_env_name(), 0..=3),
            proptest::collection::btree_map(prop_env_name(), prop_env_value(), 0..=3),
            proptest::collection::vec(1u16..=65535, 0..=3),
        )
            .prop_map(|(ro, rw, deny, mode, pass, set, ports)| {
                let rw: Vec<String> = rw.into_iter().filter(|path| !ro.contains(path)).collect();
                format!(
                    r#"{{"version": 1, "filesystem": {{"ro": {}, "rw": {}, "deny": {}}}, "network": {{"mode": {mode:?}, "allow": [], "ports": {}}}, "env": {{"pass": {}, "set": {}}}, "limits": {{"timeout": "120s", "output_bytes": 10485760}}}}"#,
                    json_list(&ro),
                    json_list(&rw),
                    json_list(&deny),
                    json_list_u16(&ports),
                    json_list(&pass),
                    json_object(&set),
                )
            })
    }

    fn json_string(value: &str) -> String {
        serde_json::Value::String(value.to_owned()).to_string()
    }

    fn json_list(values: &[String]) -> String {
        let items: Vec<String> = values.iter().map(|value| json_string(value)).collect();
        format!("[{}]", items.join(", "))
    }

    fn json_list_u16(values: &[u16]) -> String {
        let items: Vec<String> = values.iter().map(u16::to_string).collect();
        format!("[{}]", items.join(", "))
    }

    fn json_object(entries: &BTreeMap<String, String>) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(key, value)| format!("{}: {}", json_string(key), json_string(value)))
            .collect();
        format!("{{{}}}", items.join(", "))
    }

    // ---- argv parsing for the invariants ------------------------------------

    /// Structural events of the flag region (everything before the `--`
    /// tail), in emission order. The walk is ARITY-BASED: operands are
    /// skipped by their flag's arity, so an env value or path that LOOKS
    /// like a flag can never confuse it.
    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Bind { src: OsString, dest: String },
        Symlink { dest: String },
        Tmpfs { dest: String },
        Proc { dest: String },
        Dev { dest: String },
        Setenv { name: String },
        Chdir { dir: OsString },
        Flag(String),
    }

    fn parse_flags(flags: &[OsString]) -> Vec<Event> {
        fn text(arg: &OsString) -> String {
            arg.to_str()
                .unwrap_or_else(|| panic!("flag-region element is not UTF-8: {arg:?}"))
                .to_owned()
        }
        let mut events = Vec::new();
        let mut i = 0;
        while i < flags.len() {
            let flag = text(&flags[i]);
            match flag.as_str() {
                "--ro-bind" | "--bind" => {
                    events.push(Event::Bind {
                        src: flags[i + 1].clone(),
                        dest: text(&flags[i + 2]),
                    });
                    i += 3;
                }
                "--symlink" => {
                    events.push(Event::Symlink {
                        dest: text(&flags[i + 2]),
                    });
                    i += 3;
                }
                "--tmpfs" => {
                    events.push(Event::Tmpfs {
                        dest: text(&flags[i + 1]),
                    });
                    i += 2;
                }
                "--proc" => {
                    events.push(Event::Proc {
                        dest: text(&flags[i + 1]),
                    });
                    i += 2;
                }
                "--dev" => {
                    events.push(Event::Dev {
                        dest: text(&flags[i + 1]),
                    });
                    i += 2;
                }
                "--setenv" => {
                    events.push(Event::Setenv {
                        name: text(&flags[i + 1]),
                    });
                    i += 3;
                }
                "--chdir" => {
                    events.push(Event::Chdir {
                        dir: flags[i + 1].clone(),
                    });
                    i += 2;
                }
                // Two-element flags whose operand is not otherwise
                // interesting here.
                "--cap-drop" | "--hostname" => {
                    events.push(Event::Flag(flag));
                    i += 2;
                }
                _ => {
                    events.push(Event::Flag(flag));
                    i += 1;
                }
            }
        }
        events
    }

    /// Split argv into (flag region, tail): the tail is exactly
    /// `["--", command…]` — P5 asserts this, so the split can rely on it.
    fn split_tail<'a>(
        argv: &'a [OsString],
        command: &'a [OsString],
    ) -> (&'a [OsString], &'a [OsString]) {
        let tail_start = argv.len() - command.len() - 1;
        (&argv[..tail_start], &argv[tail_start..])
    }

    fn bind_dest(event: &Event) -> Option<&str> {
        match event {
            Event::Bind { dest, .. } => Some(dest),
            _ => None,
        }
    }

    proptest! {
        #[test]
        fn prop_ancestors_first_and_deny_last(
            policy_json in prop_policy_json(),
            command in prop_command(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);

            // P1 ancestors-first: whenever dest A is a path-segment prefix
            // of dest B, A mounts strictly before B (the byte-order sort
            // IS this rule — "/tmp" < "/tmp/x"; equal dests are not
            // prefixes of each other and keep their prio order).
            let dests: Vec<&str> = events.iter().filter_map(bind_dest).collect();
            for (i, a) in dests.iter().enumerate() {
                for (j, b) in dests.iter().enumerate() {
                    if b.starts_with(&format!("{a}/")) {
                        prop_assert!(
                            i < j,
                            "{:?} must precede descendant {:?}: {:?}",
                            a, b, dests
                        );
                    }
                }
            }

            // P2 deny-last: every --tmpfs comes after every
            // --ro-bind/--bind/--proc/--dev element.
            let last_fs = events.iter().rposition(|event| {
                matches!(event, Event::Bind { .. } | Event::Proc { .. } | Event::Dev { .. })
            });
            let first_deny = events
                .iter()
                .position(|event| matches!(event, Event::Tmpfs { .. }));
            if let (Some(last_fs), Some(first_deny)) = (last_fs, first_deny) {
                prop_assert!(
                    last_fs < first_deny,
                    "deny masks must come last: {:?}",
                    events
                );
            }
        }

        #[test]
        fn prop_allow_list_purity(
            policy_json in prop_policy_json(),
            command in prop_command(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);

            // P4 (part 1): NEVER --unshare-net — the netns belongs to
            // __init (module docs point 6); bwrap joins the inherited one.
            prop_assert!(
                !flags.iter().any(|arg| arg == OsStr::new("--unshare-net")),
                "--unshare-net must never be emitted"
            );

            // P4 (part 2): bind srcs ⊆ policy paths ∪ infra /etc set ∪
            // session leaves ∪ generated files; the host root and the
            // session dir itself are never a src or dest. (The session
            // dir's PARENT — /tmp for the golden inputs — can only appear
            // as a src if the POLICY itself lists it: an explicit policy
            // statement, not builder leakage; the subset check is the
            // operative rule.)
            let layout = session_layout(Path::new(SESSION_DIR));
            let mut allowed: Vec<OsString> = policy
                .filesystem
                .ro
                .iter()
                .chain(&policy.filesystem.rw)
                .map(|path| OsString::from(path.as_str()))
                .chain(INFRA_ETC.map(OsString::from))
                .collect();
            allowed.extend(
                [
                    layout.work,
                    layout.home,
                    layout.tmp,
                    layout.resolv_conf,
                    layout.passwd,
                    layout.group,
                ]
                .map(PathBuf::into_os_string),
            );
            for event in &events {
                if let Event::Bind { src, dest } = event {
                    prop_assert!(
                        allowed.contains(src),
                        "bind src outside the allow-list union: {:?}",
                        src
                    );
                    prop_assert!(src != OsStr::new("/"), "the host root must never be bound");
                    prop_assert!(dest != "/", "the host root must never be a bind dest");
                    prop_assert!(
                        src != OsStr::new(SESSION_DIR),
                        "the session dir itself must never be bound — only its leaves"
                    );
                }
            }
        }

        #[test]
        fn prop_head_tail_and_determinism(
            policy_json in prop_policy_json(),
            command in prop_command(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);

            // P5 head: argv[0] is the bwrap path verbatim.
            prop_assert!(argv[0] == OsStr::new(BWRAP));
            // P5 tail: argv ends with exactly ["--", command…] — the
            // command bytes verbatim (non-UTF-8 included).
            let (_, tail) = split_tail(&argv, &command);
            prop_assert!(tail[0] == OsStr::new("--"));
            prop_assert_eq!(&tail[1..], command.as_slice());

            // --chdir: exactly one, defaulting to /work (cwd None here),
            // immediately before the `--` separator.
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);
            let chdirs: Vec<&OsString> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Chdir { dir } => Some(dir),
                    _ => None,
                })
                .collect();
            prop_assert_eq!(chdirs.len(), 1);
            prop_assert!(chdirs[0] == OsStr::new("/work"));
            // (The matches! is hoisted out of the prop_assert!: proptest
            // stringifies the condition into a format string, where the
            // `{ .. }` pattern would be parsed as a format placeholder.)
            let last_is_chdir = matches!(events.last(), Some(Event::Chdir { .. }));
            prop_assert!(last_is_chdir, "the flag region must end with --chdir");

            // P6 determinism: identical inputs ⇒ byte-identical argv.
            let again = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
            prop_assert_eq!(argv, again);
        }

        #[test]
        fn prop_proc_dev_fixed_position(
            policy_json in prop_policy_json(),
            command in prop_command(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);

            // P7: exactly one --proc /proc and one --dev /dev, adjacent,
            // after the whole bind block and before any deny block.
            let procs: Vec<usize> = events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| matches!(e, Event::Proc { .. }).then_some(i))
                .collect();
            let devs: Vec<usize> = events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| matches!(e, Event::Dev { .. }).then_some(i))
                .collect();
            prop_assert_eq!(procs.len(), 1, "exactly one --proc: {:?}", events);
            prop_assert_eq!(devs.len(), 1, "exactly one --dev: {:?}", events);
            prop_assert_eq!(devs[0], procs[0] + 1, "--dev must directly follow --proc");
            match &events[procs[0]] {
                Event::Proc { dest } => prop_assert_eq!(dest, "/proc"),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
            match &events[devs[0]] {
                Event::Dev { dest } => prop_assert_eq!(dest, "/dev"),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
            let last_bind = events
                .iter()
                .rposition(|event| matches!(event, Event::Bind { .. }))
                .expect("the infra/session binds are unconditional");
            prop_assert!(last_bind < procs[0], "--proc must follow every bind");
            if let Some(first_deny) = events
                .iter()
                .position(|event| matches!(event, Event::Tmpfs { .. }))
            {
                prop_assert!(devs[0] < first_deny, "--dev must precede every deny mask");
            }
        }

        #[test]
        fn prop_env_contract(
            policy_json in prop_policy_json(),
            command in prop_command(),
            passed_env in prop_passed_env(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &passed_env, None, &command);
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);

            // P3: exactly one --clearenv, before every --setenv.
            let clearenvs: Vec<usize> = events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    (e == &Event::Flag("--clearenv".to_owned())).then_some(i)
                })
                .collect();
            prop_assert_eq!(
                clearenvs.len(),
                1,
                "exactly one --clearenv: {:?}",
                events
            );
            let setenvs: Vec<(usize, &String)> = events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| match e {
                    Event::Setenv { name } => Some((i, name)),
                    _ => None,
                })
                .collect();
            if let Some((first, _)) = setenvs.first() {
                prop_assert!(clearenvs[0] < *first, "--clearenv must precede every --setenv");
            }

            // P8: the setenv NAME sequence equals infra trio → pass∩passed
            // (sorted) → set keys (sorted) → proxy 8 (explicit only).
            // Sequence equality pins group order, sortedness within each
            // block, AND the proxy presence-iff-explicit rule at once.
            let mut expected: Vec<String> =
                ["HOME", "PATH", "TMPDIR"].map(String::from).to_vec();
            for name in passed_env.keys() {
                if policy.env.pass.iter().any(|allowed| allowed == name) {
                    expected.push(name.clone());
                }
            }
            expected.extend(policy.env.set.keys().cloned());
            if policy.network.mode == NetworkMode::Explicit {
                expected.extend(
                    [
                        "ALL_PROXY",
                        "HTTP_PROXY",
                        "HTTPS_PROXY",
                        "NO_PROXY",
                        "all_proxy",
                        "http_proxy",
                        "https_proxy",
                        "no_proxy",
                    ]
                    .map(String::from),
                );
            }
            let actual: Vec<&String> = setenvs.iter().map(|(_, name)| *name).collect();
            prop_assert_eq!(actual, expected.iter().collect::<Vec<&String>>());

            // P8 contiguity: the setenv events form one uninterrupted run
            // (no filesystem op interleaves the environment block).
            if let (Some(first), Some(last)) = (
                events.iter().position(|e| matches!(e, Event::Setenv { .. })),
                events.iter().rposition(|e| matches!(e, Event::Setenv { .. })),
            ) {
                let contiguous = events[first..=last]
                    .iter()
                    .all(|e| matches!(e, Event::Setenv { .. }));
                prop_assert!(contiguous, "setenv block must be contiguous: {:?}", events);
            }
        }

        #[test]
        fn prop_shim_skip_rule(
            policy_json in prop_policy_json(),
            command in prop_command(),
        ) {
            let policy = prop_policy(&policy_json);
            let argv = golden_argv_full(&policy, &BTreeMap::new(), None, &command);
            let (flags, _) = split_tail(&argv, &command);
            let events = parse_flags(flags);

            // P9: a shim is emitted ⟺ its dest is neither a bind dest nor
            // a deny path — and the emitted ones keep the fixed order
            // (/bin, /sbin, /lib, /lib64), which the sequence equality
            // pins together with the subset rule.
            let bind_dests: BTreeSet<&str> = events.iter().filter_map(bind_dest).collect();
            let denies: BTreeSet<&str> = policy
                .filesystem
                .deny
                .iter()
                .map(AbsolutePath::as_str)
                .collect();
            let actual: Vec<&str> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Symlink { dest } => Some(dest.as_str()),
                    _ => None,
                })
                .collect();
            let expected: Vec<&str> = USR_MERGE_SHIMS
                .iter()
                .map(|(dest, _)| *dest)
                .filter(|dest| !bind_dests.contains(dest) && !denies.contains(dest))
                .collect();
            prop_assert_eq!(actual, expected);
        }
    }
}
