//! Filesystem layout checks: licence files, README and CI workflow. SHA-325: the root
//! README's status line, length, section order and links.

use repo_checks::{LICENSED_CRATES, workspace_root};
use std::collections::HashMap;
use std::fs;

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn root_license_files_exist() {
    let apache = read("LICENSE-APACHE");
    assert!(apache.contains("Apache License"), "LICENSE-APACHE title");
    assert!(
        apache.contains("Version 2.0, January 2004"),
        "LICENSE-APACHE version"
    );
    assert!(
        apache.contains("END OF TERMS AND CONDITIONS"),
        "LICENSE-APACHE must be the full text"
    );

    let mit = read("LICENSE-MIT");
    assert!(mit.contains("MIT License"), "LICENSE-MIT title");
    assert!(
        mit.contains("Copyright (c) 2026 The keelsign contributors"),
        "LICENSE-MIT copyright line"
    );
    assert!(
        mit.contains("Permission is hereby granted, free of charge"),
        "LICENSE-MIT must be the full text"
    );
}

#[test]
fn root_readme_exists() {
    let readme = read("README.md");
    assert!(readme.starts_with("# keelsign"), "README heading");
    assert!(
        !readme.contains("placeholder"),
        "README must not describe the crates as placeholders"
    );
    assert!(
        readme.contains("LICENSE-APACHE"),
        "README links LICENSE-APACHE"
    );
    assert!(readme.contains("LICENSE-MIT"), "README links LICENSE-MIT");
}

/// The paragraph that starts with `**Status: pre-release.**`.
fn status_paragraph(readme: &str) -> String {
    let start = readme
        .find("**Status: pre-release.**")
        .expect("README must contain `**Status: pre-release.**`");
    let rest = &readme[start..];
    let end = rest.find("\n\n").unwrap_or(rest.len());
    rest[..end].to_string()
}

/// SHA-325: nothing is on crates.io yet, so the README must say to build from the
/// repository and must not claim a published version or planned crates.
#[test]
fn root_readme_status_is_accurate() {
    let readme = read("README.md");
    let status = status_paragraph(&readme);
    assert!(
        status.contains("crates.io"),
        "the status paragraph must say whether the crates are on crates.io:\n{status}"
    );
    assert!(
        status.contains("build from this repository"),
        "the status paragraph must say to build from this repository:\n{status}"
    );
    for stale in ["published `0.0.1`", "placeholder", "(planned)"] {
        assert!(
            !readme.contains(stale),
            "README must not contain the stale `{stale}`"
        );
    }
}

/// The text of each `## ` section, keyed by heading, in order. Headings inside code
/// fences are ignored.
fn h2_sections(markdown: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut in_fence = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
        }
        if !in_fence && let Some(heading) = line.strip_prefix("## ") {
            sections.push((heading.trim().to_string(), String::new()));
            continue;
        }
        if let Some((_, body)) = sections.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    sections
}

/// The lines of each ```` ```sh ```` block in `text`.
fn sh_blocks(text: &str) -> Vec<Vec<String>> {
    let mut blocks = Vec::new();
    // `Some(is_sh, lines)` while inside a fence.
    let mut fence: Option<(bool, Vec<String>)> = None;
    for line in text.lines() {
        let is_fence = line.starts_with("```");
        match fence.take() {
            None if is_fence => fence = Some((line.trim() == "```sh", Vec::new())),
            None => {}
            Some((true, lines)) if is_fence => blocks.push(lines),
            Some((false, _)) if is_fence => {}
            Some((is_sh, mut lines)) => {
                lines.push(line.to_string());
                fence = Some((is_sh, lines));
            }
        }
    }
    blocks
}

/// SHA-325: the README fits in about 90 lines, the status and quickstart are on the
/// first screen, the sections are the five agreed ones in order, and the Development
/// section has one `sh` block of `cargo` commands.
#[test]
fn root_readme_is_short_and_front_loaded() {
    const MAX_LINES: usize = 90;
    let readme = read("README.md");
    let lines: Vec<&str> = readme.lines().collect();
    assert!(
        lines.len() <= MAX_LINES,
        "README has {} lines; keep it to at most {MAX_LINES}",
        lines.len()
    );

    let line_of = |prefix: &str| {
        lines
            .iter()
            .position(|l| l.starts_with(prefix))
            .map(|i| i + 1)
            .unwrap_or_else(|| panic!("README must have a line starting `{prefix}`"))
    };
    let status = line_of("**Status:");
    assert!(
        status <= 10,
        "the status line is line {status}; it must be within the first 10"
    );
    let quickstart = line_of("## Quickstart");
    assert!(
        quickstart <= 15,
        "`## Quickstart` is line {quickstart}; it must be within the first 15"
    );

    let sections = h2_sections(&readme);
    let headings: Vec<&str> = sections.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(
        headings,
        [
            "Quickstart",
            "What is supported",
            "Documentation",
            "Development",
            "Licence"
        ],
        "README `##` headings"
    );

    let development = sections
        .iter()
        .find(|(h, _)| h == "Development")
        .map(|(_, body)| body.as_str())
        .expect("README must have a Development section");
    let blocks = sh_blocks(development);
    assert_eq!(
        blocks.len(),
        1,
        "the Development section must have exactly one `sh` block"
    );
    for block in &blocks {
        assert!(!block.is_empty(), "the Development `sh` block is empty");
        for line in block {
            assert!(
                line.starts_with("cargo "),
                "every line of the Development `sh` block must be a cargo command: `{line}`"
            );
        }
    }
}

/// Every inline link target `](target)` in `markdown` outside code fences, in order.
fn markdown_links(markdown: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut in_fence = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = line;
        while let Some(start) = rest.find("](") {
            let after = &rest[start + 2..];
            match after.find(')') {
                Some(end) => {
                    links.push(after[..end].to_string());
                    rest = &after[end + 1..];
                }
                None => break,
            }
        }
    }
    links
}

/// The GitHub anchor slug of each heading in `markdown`, outside code fences: lower-case,
/// punctuation other than `-` and `_` removed, spaces turned into `-`; a repeated slug
/// gets `-1`, `-2`, ... appended.
fn github_anchors(markdown: &str) -> Vec<String> {
    let mut anchors = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut in_fence = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = line.chars().take_while(|&c| c == '#').count();
        if !(1..=6).contains(&hashes) || !line[hashes..].starts_with(' ') {
            continue;
        }
        let text = line[hashes..].trim().trim_end_matches('#').trim();
        let slug: String = text
            .to_lowercase()
            .chars()
            .filter_map(|c| match c {
                ' ' => Some('-'),
                '-' | '_' => Some(c),
                c if c.is_alphanumeric() => Some(c),
                _ => None,
            })
            .collect();
        let count = seen.entry(slug.clone()).or_insert(0);
        let anchor = if *count == 0 {
            slug
        } else {
            format!("{slug}-{count}")
        };
        *count += 1;
        anchors.push(anchor);
    }
    anchors
}

/// SHA-325: every relative link in the root README points at an existing file, and
/// every anchor names a heading in that file.
#[test]
fn root_readme_links_resolve() {
    let root = workspace_root();
    let readme = read("README.md");
    let links = markdown_links(&readme);
    assert!(
        links.len() >= 15,
        "found only {} links in README.md; the link scan is broken",
        links.len()
    );
    for link in &links {
        if link.starts_with("http://") || link.starts_with("https://") {
            continue;
        }
        let (path, anchor) = match link.split_once('#') {
            Some((path, anchor)) => (path, Some(anchor)),
            None => (link.as_str(), None),
        };
        let target = if path.is_empty() { "README.md" } else { path };
        let full = root.join(target);
        assert!(
            full.is_file(),
            "README link `{link}`: {} is not a file",
            full.display()
        );
        if let Some(anchor) = anchor {
            let text = fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("read {}: {e}", full.display()));
            let anchors = github_anchors(&text);
            assert!(
                anchors.iter().any(|a| a == anchor),
                "README link `{link}`: no heading in {target} has the anchor `#{anchor}` \
                 (anchors: {anchors:?})"
            );
        }
    }
}

#[test]
fn ci_workflow_runs_fmt_clippy_test() {
    let ci = read(".github/workflows/ci.yml");
    for needle in ["cargo fmt", "cargo clippy", "cargo test", "-D warnings"] {
        assert!(ci.contains(needle), "ci.yml must contain `{needle}`");
    }
}

#[test]
fn crate_license_copies_match_root() {
    let root = workspace_root();
    for krate in LICENSED_CRATES {
        for file in ["LICENSE-APACHE", "LICENSE-MIT"] {
            let root_bytes = fs::read(root.join(file)).expect("read root licence");
            let copy_path = root.join(krate).join(file);
            let copy_bytes = fs::read(&copy_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", copy_path.display()));
            assert_eq!(
                root_bytes,
                copy_bytes,
                "{} must be byte-identical to the root {file}",
                copy_path.display()
            );
        }
    }
}
