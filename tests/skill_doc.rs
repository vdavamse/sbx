//! Consistency checks for the agent skill in `skills/sbx/` (issue #69).
//!
//! The skill quotes sbx's CLI, paths and messages, so it drifts when they change.
//! This test keeps it honest:
//!
//! * `SKILL.md` has Agent Skills frontmatter: `name` equal to the directory name
//!   and a non-empty `description` of at most 1024 characters;
//! * every `--flag` written after `sbx run|attach|stop|check|gc` in the skill
//!   exists in that subcommand's `--help`, and so does every `"--flag"` string
//!   literal in the harness wrappers in `examples/harness/`;
//! * relative links stay inside `skills/sbx/` (the skill is installed by
//!   copying that directory) and resolve, and every link into this repository
//!   on GitHub names an existing file and, with `#anchor`, an existing heading;
//! * the sbx messages the skill quotes still occur in `src/`;
//! * every infrastructure `/etc` path bound by sbx (`INFRA_ETC`) is listed in
//!   the layout table;
//! * README.md and docs/usage.md link the skill.
//!
//! The wrappers themselves are executed against a real sbx by CI
//! (`--selftest`), not here.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SKILL_DIR: &str = "skills/sbx";
const SKILL_FILES: [&str; 3] = [
    "skills/sbx/SKILL.md",
    "skills/sbx/references/agent-in-sandbox.md",
    "skills/sbx/references/harness-bash-tool.md",
];
const WRAPPERS: [&str; 2] = [
    "examples/harness/sbx_bash_tool.py",
    "examples/harness/sbx_bash_tool.ts",
];
const SUBCOMMANDS: [&str; 5] = ["run", "attach", "stop", "check", "gc"];
const REPO_URL: &str = "https://github.com/vdavamse/sbx/";

/// Messages the skill quotes verbatim (or as a prefix); each must still be
/// produced somewhere in `src/`.
const QUOTED_MESSAGES: [&str; 4] = [
    "session directory is in use",
    "output truncated at",
    "timed out after",
    "is not in the policy allow list",
];

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read(rel: &str) -> String {
    let path = repo_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn help(sub: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args([sub, "--help"])
        .output()
        .expect("run sbx --help");
    assert!(out.status.success(), "sbx {sub} --help failed");
    String::from_utf8(out.stdout).expect("utf-8 help")
}

/// True when `flag` occurs in `text` as a whole option name.
fn has_flag(text: &str, flag: &str) -> bool {
    text.match_indices(flag).any(|(i, _)| {
        let next = text[i + flag.len()..].chars().next();
        !matches!(next, Some(c) if c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// Strips the decoration around a token in prose or code: brackets, backticks,
/// quotes, trailing punctuation and an `=value`.
fn clean_flag(tok: &str) -> Option<&str> {
    let t = tok.trim_matches(|c: char| "[]()`'\",.;:".contains(c));
    let t = t.split('=').next().unwrap_or(t);
    let ok = t.len() > 2
        && t.starts_with("--")
        && t[2..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    ok.then_some(t)
}

/// (subcommand, flag, file:line) for every flag written after `sbx SUB`, up to
/// the end of the command (a standalone `--`, or the line end unless it is
/// continued with `\`).
fn flags_in_docs() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for rel in SKILL_FILES {
        let text = read(rel);
        let lines: Vec<&str> = text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            for (i, tok) in toks.iter().enumerate() {
                if tok.trim_start_matches('`') != "sbx" {
                    continue;
                }
                let Some(sub) = toks.get(i + 1).map(|s| s.trim_matches('`')) else {
                    continue;
                };
                if !SUBCOMMANDS.contains(&sub) {
                    continue;
                }
                let mut rest: Vec<&str> = toks[i + 2..].to_vec();
                let mut j = idx;
                while rest.last() == Some(&"\\") && j + 1 < lines.len() {
                    rest.pop();
                    j += 1;
                    rest.extend(lines[j].split_whitespace());
                }
                for tok in rest {
                    if tok == "--" || tok.starts_with("--`") {
                        break;
                    }
                    if let Some(flag) = clean_flag(tok) {
                        found.push((
                            sub.to_string(),
                            flag.to_string(),
                            format!("{rel}:{}", idx + 1),
                        ));
                    }
                    // A closing backtick ends an inline code span, and with it the command.
                    if tok
                        .trim_end_matches(|c: char| ".,;:)".contains(c))
                        .ends_with('`')
                    {
                        break;
                    }
                }
            }
        }
    }
    found
}

#[test]
fn frontmatter_names_the_skill() {
    let text = read("skills/sbx/SKILL.md");
    let body = text
        .strip_prefix("---\n")
        .expect("SKILL.md starts with --- frontmatter");
    let (front, _) = body
        .split_once("\n---\n")
        .expect("frontmatter is closed by ---");
    let field = |key: &str| {
        front
            .lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(':')))
            .map(str::trim)
            .unwrap_or_else(|| panic!("frontmatter has no {key}"))
    };
    let dir = Path::new(SKILL_DIR).file_name().unwrap().to_str().unwrap();
    assert_eq!(field("name"), dir, "name must match the skill directory");
    let desc = field("description");
    assert!(
        !desc.is_empty() && desc.chars().count() <= 1024,
        "description must be 1..=1024 chars"
    );
}

#[test]
fn documented_flags_exist() {
    let helps: Vec<(&str, String)> = SUBCOMMANDS.iter().map(|s| (*s, help(s))).collect();
    let help_of = |sub: &str| &helps.iter().find(|(s, _)| *s == sub).unwrap().1;
    let found = flags_in_docs();
    assert!(
        found.len() >= 20,
        "the flag scanner found only {} flags",
        found.len()
    );
    let mut missing = Vec::new();
    for (sub, flag, at) in &found {
        if !has_flag(help_of(sub), flag) {
            missing.push(format!("{at}: sbx {sub} {flag}"));
        }
    }
    let run_help = help_of("run");
    for rel in WRAPPERS {
        for (idx, line) in read(rel).lines().enumerate() {
            for lit in line.split('"').skip(1).step_by(2) {
                if lit == "--selftest" || lit == "--" {
                    continue;
                }
                if let Some(flag) = clean_flag(lit).filter(|f| *f == lit) {
                    if !has_flag(run_help, flag) {
                        missing.push(format!("{rel}:{}: sbx run {flag}", idx + 1));
                    }
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "flags not in sbx --help:\n{}",
        missing.join("\n")
    );
}

/// GitHub's heading anchor: lowercase, spaces to `-`, punctuation dropped.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

fn anchors(rel: &str) -> Vec<String> {
    read(rel)
        .lines()
        .filter_map(|l| {
            l.trim_start_matches('#')
                .strip_prefix(' ')
                .filter(|_| l.starts_with('#'))
        })
        .map(slug)
        .collect()
}

#[test]
fn links_resolve() {
    let mut bad = Vec::new();
    for rel in SKILL_FILES {
        let text = read(rel);
        for part in text.split("](").skip(1) {
            let Some(target) = part.split(')').next() else {
                continue;
            };
            let (path, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target, None),
            };
            if let Some(rest) = path.strip_prefix(REPO_URL) {
                let file = rest
                    .strip_prefix("blob/main/")
                    .or_else(|| rest.strip_prefix("tree/main/"))
                    .unwrap_or_else(|| panic!("{rel}: link {target} is not on main"));
                let file = file.trim_end_matches('/');
                if !repo_path(file).exists() {
                    bad.push(format!("{rel}: {target}: no such file"));
                } else if let Some(a) = anchor {
                    if !anchors(file).iter().any(|s| s == a) {
                        bad.push(format!("{rel}: {target}: no such heading"));
                    }
                }
            } else if path.starts_with("http") {
                continue;
            } else {
                let base = repo_path(rel).parent().unwrap().to_path_buf();
                let resolved = base.join(path);
                let inside = resolved
                    .canonicalize()
                    .map(|p| p.starts_with(repo_path(SKILL_DIR).canonicalize().unwrap()))
                    .unwrap_or(false);
                if !inside {
                    bad.push(format!(
                        "{rel}: {target}: relative links must resolve inside {SKILL_DIR} (use a {REPO_URL} link)"
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "bad links:\n{}", bad.join("\n"));
}

/// All `.rs` sources under `src/`, concatenated.
fn all_src() -> String {
    fn walk(dir: &Path, out: &mut String) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push_str(&fs::read_to_string(&path).unwrap());
            }
        }
    }
    let mut out = String::new();
    walk(&repo_path("src"), &mut out);
    out
}

#[test]
fn quoted_messages_exist() {
    let src = all_src();
    // Prose wraps lines, so compare with whitespace runs folded to one space.
    let skill: String = SKILL_FILES
        .iter()
        .map(|f| read(f).split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(" ");
    for msg in QUOTED_MESSAGES {
        assert!(
            skill.contains(msg),
            "the skill no longer quotes {msg:?}; update QUOTED_MESSAGES"
        );
        assert!(
            src.contains(msg),
            "sbx no longer prints {msg:?}, but the skill quotes it"
        );
    }
}

#[test]
fn layout_table_lists_infra_etc() {
    let argv = read("src/bwrap/argv.rs");
    let start = argv
        .find("INFRA_ETC: [&str;")
        .expect("INFRA_ETC in src/bwrap/argv.rs");
    let list = &argv[start..start + argv[start..].find("];").unwrap()];
    let skill = read("skills/sbx/SKILL.md");
    let paths: Vec<&str> = list.split('"').skip(1).step_by(2).collect();
    assert!(!paths.is_empty());
    for p in paths {
        let name = p.strip_prefix("/etc/").expect("an /etc path");
        assert!(
            skill.contains(&format!("`{name}`")),
            "SKILL.md layout table does not list {p}"
        );
    }
}

#[test]
fn readme_and_usage_link_the_skill() {
    for rel in ["README.md", "docs/usage.md"] {
        assert!(
            read(rel).contains("skills/sbx"),
            "{rel} does not link skills/sbx"
        );
    }
}
