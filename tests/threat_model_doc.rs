//! Consistency checks for `docs/threat-model.md` (issue #14).
//!
//! The threat model cites conformance checks by id and cites code as
//! `src/<file>.rs:<identifier>`. This test keeps those citations honest:
//!
//! * every backticked check id in the document exists in the catalog;
//! * every catalog check is cited in the guarantee table (section 6);
//! * every "N checks" / "N catalog checks" / "N executable checks" statement in
//!   the document and the README equals the catalog size;
//! * every `src/...:identifier` reference names a file that exists and an
//!   identifier that occurs in it as a whole word;
//! * README.md and SECURITY.md link the document.
//!
//! No regex crate is used; the scanners are hand-written.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sbx::conformance::catalog::{self, CATALOG};

const DOC: &str = "docs/threat-model.md";
const LINK: &str = "docs/threat-model.md";
const SECTION6_START: &str = "## 6. ";
const SECTION6_END: &str = "## 7. ";

fn read_repo_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// True for a check-id shape: one uppercase ASCII letter, then two digits.
/// Shape only: whether the id exists is checked against the catalog, so a
/// made-up id such as `Z99` or `A13` is reported as unknown.
fn is_check_id(tok: &str) -> bool {
    let b = tok.as_bytes();
    b.len() == 3 && b[0].is_ascii_uppercase() && b[1].is_ascii_digit() && b[2].is_ascii_digit()
}

/// The non-fenced lines of a Markdown document (lines inside ``` fences are dropped).
fn prose_lines(doc: &str) -> Vec<&str> {
    let mut in_fence = false;
    let mut out = Vec::new();
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push(line);
        }
    }
    out
}

/// The contents of every inline code span on a line. Spans alternate with
/// prose; a span runs between two backticks on the same line.
fn code_spans(line: &str) -> Vec<&str> {
    line.split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s)
        .collect()
}

/// Every check-id-shaped code span in the given lines.
fn ids_in(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .flat_map(|l| code_spans(l))
        .filter(|s| is_check_id(s))
        .map(str::to_owned)
        .collect()
}

/// The section 6 table rows: the lines between the section 6 and section 7 headings.
fn section6_rows(doc: &str) -> Vec<&str> {
    let lines = prose_lines(doc);
    let start = lines
        .iter()
        .position(|l| l.starts_with(SECTION6_START))
        .expect("doc has no section 6 heading");
    let end = lines
        .iter()
        .position(|l| l.starts_with(SECTION6_END))
        .expect("doc has no section 7 heading");
    assert!(start < end, "section 6 must come before section 7");
    lines[start..end]
        .iter()
        .copied()
        .filter(|l| l.starts_with('|'))
        .collect()
}

/// Every "<N> checks", "<N> catalog checks" and "<N> executable checks" phrase
/// in the lines, as the number N. Hand-parsed over whitespace-separated words.
fn stated_check_counts(lines: &[&str]) -> Vec<usize> {
    let mut out = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            let Ok(n) = w.parse::<usize>() else { continue };
            let next = words.get(i + 1).copied();
            let after = words.get(i + 2).copied();
            let is_count = match next {
                Some("checks") => true,
                Some("catalog") | Some("executable") => after == Some("checks"),
                _ => false,
            };
            if is_count {
                out.push(n);
            }
        }
    }
    out
}

/// True when `word` occurs in `text` delimited by non-identifier characters.
fn contains_word(text: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// `src/...:identifier` code spans, as (path, identifier). The identifier is
/// the last `::` segment of the text after the first colon.
fn source_refs(lines: &[&str]) -> Vec<(String, String)> {
    lines
        .iter()
        .flat_map(|l| code_spans(l))
        .filter(|s| s.starts_with("src/") && s.contains(':'))
        .filter_map(|s| {
            let (path, ident) = s.split_once(':')?;
            let last = ident.rsplit("::").next()?.trim();
            Some((path.to_owned(), last.to_owned()))
        })
        .collect()
}

#[test]
fn every_cited_check_id_exists_in_the_catalog() {
    let doc = read_repo_file(DOC);
    let cited = ids_in(&prose_lines(&doc));
    assert!(!cited.is_empty(), "{DOC} cites no check ids at all");

    let unknown: Vec<&String> = cited
        .iter()
        .filter(|id| catalog::find(id).is_none())
        .collect();
    assert!(
        unknown.is_empty(),
        "{DOC} cites check ids that are not in the conformance catalog: {unknown:?}"
    );
}

#[test]
fn every_catalog_check_is_cited_in_the_guarantee_table() {
    let doc = read_repo_file(DOC);
    let rows = section6_rows(&doc);
    assert!(!rows.is_empty(), "{DOC} section 6 has no table rows");
    let cited: BTreeSet<String> = ids_in(&rows).into_iter().collect();

    let missing: Vec<&str> = CATALOG
        .iter()
        .map(|d| d.id)
        .filter(|id| !cited.contains(*id))
        .collect();
    assert!(
        missing.is_empty(),
        "{DOC} section 6 does not cite these catalog checks: {missing:?}"
    );
}

#[test]
fn stated_check_counts_match_the_catalog() {
    let total = CATALOG.len();
    for (name, text) in [
        (DOC, read_repo_file(DOC)),
        ("README.md", read_repo_file("README.md")),
    ] {
        let counts = stated_check_counts(&prose_lines(&text));
        assert!(
            !counts.is_empty(),
            "{name} states no check count; expected \"{total} checks\""
        );
        let wrong: Vec<usize> = counts.iter().copied().filter(|&n| n != total).collect();
        assert!(
            wrong.is_empty(),
            "{name} states check counts {wrong:?}, but the catalog has {total}"
        );
    }
}

#[test]
fn source_references_resolve() {
    let doc = read_repo_file(DOC);
    let refs = source_refs(&prose_lines(&doc));
    assert!(
        !refs.is_empty(),
        "{DOC} has no src/...:identifier references"
    );

    let mut broken = Vec::new();
    for (path, ident) in &refs {
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        match fs::read_to_string(&full) {
            Err(_) => broken.push(format!("{path} (file missing)")),
            Ok(text) if !contains_word(&text, ident) => {
                broken.push(format!("{path}:{ident} (identifier not found)"));
            }
            Ok(_) => {}
        }
    }
    assert!(
        broken.is_empty(),
        "{DOC} has references that do not resolve: {broken:?}"
    );
}

#[test]
fn readme_and_security_link_the_threat_model() {
    for file in ["README.md", "SECURITY.md"] {
        let text = read_repo_file(file);
        assert!(
            text.contains(LINK),
            "{file} must link {LINK} (the threat model)"
        );
    }
}
