//! The bwrap launcher-argv builder (issue #6) — a pure, deterministic
//! function from a validated policy + session directory to the complete
//! unmodified-bwrap invocation.
//!
//! 1. **Ownership & purity** — [`build`] is pure argv assembly: no I/O, no
//!    spawn, no filesystem probing; deterministic for identical inputs.
//!    Consumers: #10 spawns [`Launch::command`], #11 reports
//!    discovery/version via [`version`], #13 reuses the goldens' flag
//!    vocabulary. Materialization ([`etc::SessionLayout::materialize`]) is
//!    the caller's separate step.
//! 2. **Fail-closed validation** — the builder rejects before the kernel
//!    sees anything ("what we validate must be what the kernel sees" — the
//!    `check_path` NUL rationale in [`crate::policy`]): absolute bwrap path
//!    / session dir / cwd, non-empty command, no NUL in any emitted byte
//!    (paths, command elements, `--setenv` values). Binds are plain
//!    (`--ro-bind`/`--bind`, never the `-try` variants): a missing host
//!    path aborts bwrap ⇒ the sandbox never starts (Q9; #11 pre-detects
//!    and reports).
//! 3. **Allow-list purity** — the sandbox filesystem is exactly: policy
//!    binds + the infra `/etc` set + generated `/etc` files + the three
//!    session leaves. The host root is never bound (`AbsolutePath` rejects
//!    `/` — a type-level guarantee since the validity invariant landed),
//!    the session dir's PARENT is never bound (only the `work/`, `home/`,
//!    `tmp/` leaves), and there is no fd-passing (`--ro-bind-data` is
//!    impossible: #5's `fd_hygiene` closes every fd > 2 before exec —
//!    hence on-disk synthetic files, Q6).
//! 4. **Order is semantics** — bwrap applies filesystem ops in argv order.
//!    All mounts sort by (dest ascending byte order, priority ascending):
//!    byte order puts ancestors before descendants (ro parent before nested
//!    rw; `/tmp` before its contents); priority (policy 0 < infra 1 <
//!    session 2) plus bwrap's last-mount-wins makes infra/session win
//!    same-dest collisions (Q13, golden-pinned). `--proc /proc --dev /dev`
//!    follow all binds (any policy bind under `/proc`/`/dev` is silently
//!    covered — documented limitation); deny `--tmpfs` masks come last so
//!    deny always wins (Q5). Exact `(op, src, dest)` duplicates collapse
//!    (max priority kept).
//! 5. **Environment contract** — `--clearenv` plus explicit `--setenv`
//!    only; the SPAWNER must `env_clear()` ([`Launch::command`] encodes it
//!    exactly once): bwrap itself is pid 1 in the sandbox, so its spawn
//!    environment is world-readable inside at `/proc/1/environ` —
//!    `--clearenv` alone cleans only the payload (issue #6 rationale;
//!    pinned by the `secret-env-absent` integration scenario). Emission
//!    order: infra (`HOME`, `PATH`, `TMPDIR` — alphabetical) → resolved
//!    `env.pass` → `env.set` → explicit-mode proxy vars; later groups
//!    override earlier ones by name (bwrap last-`--setenv`-wins), so policy
//!    can override `PATH`/`HOME` but NOT the proxy vars in explicit mode
//!    (infra decides; documented) — nor `PWD`, which is not sbx's to
//!    decide at all: bwrap itself re-exports `PWD` from `--chdir` after
//!    every `--setenv` (bubblewrap.c v0.9.0 `xsetenv("PWD", new_cwd, 1)`),
//!    so a policy `env.set {"PWD": …}` is silently clobbered (pinned by
//!    the `secret-env-absent` integration scenario).
//! 6. **No `--unshare-net`, ever** — the network namespace belongs to
//!    `sbx __init` (#5): bwrap joins the inherited netns where the
//!    nftables rules and listeners already live. A proptest invariant pins
//!    the flag's absence for every generated policy.
//! 7. **Process isolation & hardening** — `--unshare-user --unshare-pid
//!    --unshare-ipc --unshare-uts --unshare-cgroup-try` (never host
//!    `/proc`; `cgroup-try` tolerates hosts without a cgroup ns) and
//!    `--disable-userns --cap-drop ALL --die-with-parent --new-session
//!    --hostname sandbox`. `--disable-userns` needs bwrap ≥ 0.8
//!    ([`version::BWRAP_MIN`]); it works because `--unshare-user` is
//!    present (the kernel rejects disable-userns without a private userns).
//!    HANDOFF NOTE: `--die-with-parent` fires on the parent THREAD's death
//!    — #10 must spawn from the thread that waits.
//! 8. **usr-merge shims** — `--symlink usr/bin /bin` etc. for `/bin`
//!    `/sbin` `/lib` `/lib64` (relative targets, matching the host
//!    usrmerge convention), emitted before the binds, and SKIPPED for any
//!    dest that is a bind dest or a deny dest: a mount/`--tmpfs` on a
//!    symlink FOLLOWS the link, so leaving the shim would silently redirect
//!    the op onto `/usr/*`. A dangling `/lib64` shim on hosts without
//!    `usr/lib64` is harmless (symlink(2) does not require the target to
//!    exist; resolution yields ENOENT exactly like absence, and no
//!    interpreter references it there). Non-merged hosts are documented as
//!    unsupported-with-shims (the goldens pin the four shims; #13 covers
//!    conformance).
//! 9. **Discovery & version** — [`version::find_bwrap`] (`SBX_BWRAP`
//!    override → PATH scan → fixed fallbacks) and
//!    [`version::parse_version`] against [`version::BWRAP_MIN`]; the
//!    builder takes an already-resolved ABSOLUTE path (Q10) because
//!    argv\[0\] is exec'd by `__init`'s `execvp` in an environment #10
//!    empties (R16 — no PATH ⇒ no search).
//! 10. **Layout materialization** — [`etc`] defines the session layout and
//!     the synthetic `/etc` files (pinned contents); `materialize` is
//!     idempotent so retries and `sbx gc` (#12) interplay stay simple.

pub mod etc;
pub mod version;

// Private: the argv layout is the module's implementation detail — `build`
// (below) is the public face together with `etc` (layout/materialization)
// and `version` (discovery), mirroring `init`'s two-tier visibility.
mod argv;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use crate::policy::Policy;

/// Why the builder rejected an input.
///
/// `Display` is the reason ONLY (the [`crate::policy::PolicyError`] /
/// [`crate::policy::DomainError`] precedent): #10 composes any prefix
/// (`sbx run: …`) at its own seam. Every reason is a pinned string —
/// `golden_error_pins` asserts them byte-exact.
#[derive(Debug)]
pub struct BwrapError(String);

impl std::fmt::Display for BwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BwrapError {}

/// Everything [`build`] needs — the pure argv-assembly input bag (pub
/// fields, the [`Policy`] precedent).
pub struct Build<'a> {
    /// The policy to enforce. Every `Policy`-producing path validates
    /// (policy module docs point 5), so the builder can rely on the
    /// value-level invariants (`AbsolutePath` canonical + NUL-free,
    /// POSIX env names).
    pub policy: &'a Policy,
    /// Host-side session directory; must be absolute — bwrap would
    /// resolve a relative one against its OWN cwd, not the spawner's.
    pub session_dir: &'a Path,
    /// Resolved bwrap binary ([`version::find_bwrap`] output); must be
    /// absolute — argv\[0\] is exec'd by `__init`'s `execvp` with no PATH
    /// to search (R16).
    pub bwrap_path: &'a Path,
    /// The payload command, emitted verbatim after `--` (Q12: no shell
    /// wrapping — that is #10's decision). Must be non-empty.
    pub command: &'a [OsString],
    /// Working directory INSIDE the sandbox (the cli.rs `--cwd`
    /// contract); `None` ⇒ [`etc::DEST_WORK`].
    pub cwd: Option<&'a Path>,
    /// #10's pre-resolved `env.pass` values (Q11): host values for the
    /// pass names, absent names omitted. Emission is filtered by policy
    /// membership — a buggy resolver can never inject a name the policy
    /// did not allow.
    pub passed_env: &'a BTreeMap<String, OsString>,
}

/// A complete, validated bwrap invocation.
#[derive(Debug)]
pub struct Launch {
    // Private: consumers go through argv()/command() so the env_clear
    // spawn contract stays encoded in exactly one place (module docs
    // point 5).
    argv: Vec<OsString>,
}

impl Launch {
    /// The full bwrap argv — argv\[0\] is the absolute bwrap path, the tail
    /// is `--` + the command verbatim.
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    /// A [`std::process::Command`] for this launch, with the `env_clear()`
    /// contract applied — THE single encoding site of the spawner-side
    /// environment rule (module docs point 5): bwrap is pid 1 inside the
    /// sandbox and its spawn environment is world-readable at
    /// `/proc/1/environ`, so `--clearenv` alone is not enough.
    ///
    /// The `argv[0]` index is safe: [`build`] guarantees a non-empty argv
    /// (bwrap path first, and a non-empty command is validated).
    pub fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.argv[0]);
        command.args(&self.argv[1..]);
        command.env_clear();
        command
    }
}

/// Assemble the complete bwrap argv for `input` — pure, deterministic, no
/// I/O (module docs point 1).
///
/// Validation runs first and fails closed (module docs point 2); the ten
/// rejection reasons below are pinned byte-exact by `golden_error_pins`.
/// The "validated == what the kernel sees" principle applies to NUL in
/// particular: `std::process::Command` fails closed on NUL anyway, but the
/// builder pre-rejects so the ONLY error surface for a bad build is
/// [`BwrapError`] with sbx's own vocabulary — #10 never translates an
/// opaque spawn `InvalidInput`.
pub fn build(input: &Build<'_>) -> Result<Launch, BwrapError> {
    // Row 1: bwrap path absolute (R16 — execvp without a PATH).
    if !input.bwrap_path.is_absolute() {
        return Err(BwrapError(format!(
            "bwrap path must be absolute (got {:?})",
            input.bwrap_path
        )));
    }
    // Row 2: bwrap path NUL-free.
    if contains_nul(input.bwrap_path.as_os_str()) {
        return Err(BwrapError(format!(
            "bwrap path must not contain NUL bytes (got {:?})",
            input.bwrap_path
        )));
    }
    // Row 3: session dir absolute (bwrap resolves relative paths against
    // its own cwd, not the spawner's).
    if !input.session_dir.is_absolute() {
        return Err(BwrapError(format!(
            "session directory must be absolute (got {:?})",
            input.session_dir
        )));
    }
    // Row 4: session dir NUL-free.
    if contains_nul(input.session_dir.as_os_str()) {
        return Err(BwrapError(format!(
            "session directory must not contain NUL bytes (got {:?})",
            input.session_dir
        )));
    }
    // Rows 5–6: cwd (when given) absolute and NUL-free.
    if let Some(cwd) = input.cwd {
        if !cwd.is_absolute() {
            return Err(BwrapError(format!("cwd must be absolute (got {cwd:?})")));
        }
        if contains_nul(cwd.as_os_str()) {
            return Err(BwrapError(format!(
                "cwd must not contain NUL bytes (got {cwd:?})"
            )));
        }
    }
    // Row 7: non-empty command — the exact exec_payload wording
    // (init/mod.rs): one vocabulary for "nothing to exec" across the chain.
    if input.command.is_empty() {
        return Err(BwrapError("no payload command given".to_owned()));
    }
    // Row 8: every command element NUL-free (the "interior NUL byte"
    // vocabulary matches exec_payload's).
    for (index, element) in input.command.iter().enumerate() {
        if contains_nul(element) {
            return Err(BwrapError(format!(
                "command[{index}] contains an interior NUL byte"
            )));
        }
    }
    // Row 9: every env.set value NUL-free — TODO(#6)(b), resolved here at
    // the builder seam: policy deliberately leaves values unrestricted
    // (env_values_unrestricted), and this is the point where a value
    // becomes a kernel-visible `--setenv` operand.
    for (key, value) in &input.policy.env.set {
        if value.contains('\0') {
            return Err(BwrapError(format!(
                "env.set value for {key:?} contains an interior NUL byte"
            )));
        }
    }
    // Row 10: every EMITTED passed_env value NUL-free. Only pass members
    // are emitted (the argv.rs membership filter), so only those need the
    // check — and non-POSIX KEYS need no separate check: a passed_env key
    // reaches the argv only by being a pass name, and pass names are
    // POSIX-validated at the deserialize level (the policy validity
    // invariant — see the policy module doc point 5's residual
    // struct-literal gap), hence NUL-free.
    for (name, value) in input.passed_env {
        if input.policy.env.pass.iter().any(|allowed| allowed == name) && contains_nul(value) {
            return Err(BwrapError(format!(
                "passed env value for {name:?} contains an interior NUL byte"
            )));
        }
    }
    // Infallible from here (module docs point 1): the argv layout itself
    // has no failure modes — every rejected input class is covered above.
    Ok(Launch {
        argv: argv::assemble(input),
    })
}

// NUL cannot cross any C-string interface (execvp's argv/environ, bwrap's
// own parsing): the policy module's check_path rationale, applied to the
// bytes the builder emits.
fn contains_nul(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    /// A minimal valid policy for the error pins (draft shape; `pass`
    /// carries LANG so row 10 has an emitted entry to test with).
    const POLICY: &str = r#"{
      "version": 1,
      "filesystem": { "ro": [], "rw": [], "deny": [] },
      "network": { "mode": "none", "allow": [], "ports": [] },
      "env": { "pass": ["LANG"], "set": {} },
      "limits": { "timeout": "1s", "output_bytes": 0 }
    }"#;

    /// [`POLICY`] with a NUL inside an env.set VALUE — legal per the
    /// policy schema (values unrestricted), rejected by build() row 9
    /// (TODO(#6)(b) at the builder seam). `\u0000` is serde_json's escape
    /// for the NUL character.
    const POLICY_NUL_SET: &str = r#"{
      "version": 1,
      "filesystem": { "ro": [], "rw": [], "deny": [] },
      "network": { "mode": "none", "allow": [], "ports": [] },
      "env": { "pass": ["LANG"], "set": { "SBX": "a\u0000b" } },
      "limits": { "timeout": "1s", "output_bytes": 0 }
    }"#;

    fn policy_of(json: &str) -> Policy {
        Policy::from_json_str(json).unwrap_or_else(|err| panic!("fixture must parse: {err}"))
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn os_bytes(bytes: &[u8]) -> OsString {
        OsString::from_vec(bytes.to_vec())
    }

    /// The valid baseline input — each error-pin case breaks exactly one
    /// row of the validation table.
    fn base_input<'a>(
        policy: &'a Policy,
        command: &'a [OsString],
        passed_env: &'a BTreeMap<String, OsString>,
    ) -> Build<'a> {
        Build {
            policy,
            session_dir: Path::new("/tmp/sbx-golden-session"),
            bwrap_path: Path::new("/usr/bin/bwrap"),
            command,
            cwd: None,
            passed_env,
        }
    }

    #[test]
    fn golden_error_pins() {
        // One case per row of build()'s validation table — assert_eq
        // against the exact pinned string (the BwrapError Display ==
        // reason-only contract is pinned transitively: no prefix, no
        // suffix). Goldens are intentionally brittle: any message edit is
        // a deliberate, reviewed change.
        let policy = policy_of(POLICY);
        let command = os(&["/bin/echo", "hi"]);
        let no_env = BTreeMap::new();
        let err = |input: &Build<'_>| build(input).expect_err("must be rejected").to_string();

        // Row 1: bwrap path absolute.
        let mut input = base_input(&policy, &command, &no_env);
        input.bwrap_path = Path::new("relative/bwrap");
        assert_eq!(
            err(&input),
            r#"bwrap path must be absolute (got "relative/bwrap")"#
        );

        // Row 2: bwrap path NUL-free. (`Path` is just an `OsStr` view, so
        // it CAN hold interior NULs — build() rejects them here, before
        // any spawn or C-string interface sees them.)
        let nul_bwrap = os_bytes(b"/usr/bin/bwrap\0");
        input.bwrap_path = Path::new(&nul_bwrap);
        assert_eq!(
            err(&input),
            r#"bwrap path must not contain NUL bytes (got "/usr/bin/bwrap\0")"#
        );
        input.bwrap_path = Path::new("/usr/bin/bwrap");

        // Row 3: session dir absolute.
        input.session_dir = Path::new("relative/session");
        assert_eq!(
            err(&input),
            r#"session directory must be absolute (got "relative/session")"#
        );

        // Row 4: session dir NUL-free.
        let nul_session = os_bytes(b"/tmp/sbx\0session");
        input.session_dir = Path::new(&nul_session);
        assert_eq!(
            err(&input),
            r#"session directory must not contain NUL bytes (got "/tmp/sbx\0session")"#
        );
        input.session_dir = Path::new("/tmp/sbx-golden-session");

        // Row 5: cwd absolute (when given).
        input.cwd = Some(Path::new("work/sub"));
        assert_eq!(err(&input), r#"cwd must be absolute (got "work/sub")"#);

        // Row 6: cwd NUL-free.
        let nul_cwd = os_bytes(b"/work\0sub");
        input.cwd = Some(Path::new(&nul_cwd));
        assert_eq!(
            err(&input),
            r#"cwd must not contain NUL bytes (got "/work\0sub")"#
        );

        // Row 7: non-empty command — the exact exec_payload wording.
        let empty: Vec<OsString> = Vec::new();
        let input = base_input(&policy, &empty, &no_env);
        assert_eq!(err(&input), "no payload command given");

        // Row 8: command elements NUL-free (index reported).
        let nul_command = vec![OsString::from("/bin/echo"), os_bytes(b"hi\0")];
        let input = base_input(&policy, &nul_command, &no_env);
        assert_eq!(err(&input), "command[1] contains an interior NUL byte");

        // Row 9: env.set values NUL-free (TODO(#6)(b) at the seam).
        let nul_policy = policy_of(POLICY_NUL_SET);
        let input = base_input(&nul_policy, &command, &no_env);
        assert_eq!(
            err(&input),
            r#"env.set value for "SBX" contains an interior NUL byte"#
        );

        // Row 10: emitted passed_env values NUL-free.
        let mut passed = BTreeMap::new();
        passed.insert("LANG".to_owned(), os_bytes(b"C\0"));
        let input = base_input(&policy, &command, &passed);
        assert_eq!(
            err(&input),
            r#"passed env value for "LANG" contains an interior NUL byte"#
        );

        // Row 10's scope is exactly the EMITTED entries: a NUL-carrying
        // value under a name the policy does NOT pass is never emitted
        // (the argv.rs membership filter), so it does not reject — the
        // resolver-bug backstop drops it silently instead.
        let mut passed = BTreeMap::new();
        passed.insert("LANG".to_owned(), OsString::from("C.UTF-8"));
        passed.insert("EVIL".to_owned(), os_bytes(b"x\0"));
        let input = base_input(&policy, &command, &passed);
        let launch = build(&input).expect("a non-emitted NUL value must not reject");
        assert!(launch.argv().iter().all(|element| !contains_nul(element)));
    }

    #[test]
    fn launch_command_pins_argv_and_env_clear() {
        // Golden 11: Launch::command() is THE single encoding site of the
        // spawn contract (module docs point 5): program == argv[0], args
        // == argv[1..], environment cleared.
        let policy = policy_of(POLICY);
        let command = os(&["/bin/echo", "hi"]);
        let no_env = BTreeMap::new();
        let launch =
            build(&base_input(&policy, &command, &no_env)).expect("valid inputs must build");
        let spawned = launch.command();
        assert_eq!(spawned.get_program(), OsStr::new("/usr/bin/bwrap"));
        let args: Vec<&OsStr> = spawned.get_args().collect();
        assert_eq!(args, &launch.argv()[1..]);
        // Command::get_envs is stable since 1.75 ≤ MSRV 1.85 (the msrv CI
        // job is the backstop): env_clear() must leave the environment
        // map EMPTY — the spawner-side half of the /proc/1/environ
        // contract. If this ever fails to compile on the MSRV, drop this
        // assertion and rely on the integration pin (secret-env-absent).
        assert_eq!(
            spawned.get_envs().next(),
            None,
            "env_clear() must be applied"
        );
    }

    #[test]
    fn bwrap_error_display_is_reason_only() {
        // The Display == reason contract (#10 composes any prefix): no
        // "sbx bwrap:"-style decoration at this layer.
        let err = BwrapError("no payload command given".to_owned());
        assert_eq!(err.to_string(), "no payload command given");
        // std::error::Error is implemented (the PolicyError precedent) so
        // ? and anyhow-style consumers work at #10's seam.
        let boxed: Box<dyn std::error::Error> = Box::new(BwrapError("x".to_owned()));
        assert_eq!(boxed.to_string(), "x");
    }
}
