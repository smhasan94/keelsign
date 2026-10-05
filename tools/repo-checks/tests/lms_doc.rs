//! SHA-69: docs/lms.md, the plain-language document on stateful LMS/HSS keys, has the
//! sections and warnings the ticket asks for, the README and the key and signing docs link
//! it, and (NEEDS-HUMAN) its plain-language review is recorded.

use repo_checks::workspace_root;
use std::fs;

const LMS_DOC: &str = "docs/lms.md";

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of the `## ` section `heading` (up to the next `## ` heading).
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(&format!("\n## {heading}\n"))
        .unwrap_or_else(|| panic!("{LMS_DOC} has no `## {heading}` section"));
    let body = &doc[start + heading.len() + 5..];
    &body[..body.find("\n## ").unwrap_or(body.len())]
}

/// Text with every run of whitespace (line breaks included) collapsed to one space.
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// SHA-69 AC3: docs/lms.md explains why a stateful key is dangerous, what a reused leaf
/// leaks, the one-tree-one-L rule, the handling rules (moved from keys.md), what a
/// production signing service needs, a glossary and the review record.
#[test]
fn lms_doc_has_required_sections_and_warnings() {
    let doc = read(LMS_DOC);
    assert!(
        doc.starts_with("# LMS/HSS: stateful keys (SHA-69)\n"),
        "{LMS_DOC} title"
    );
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(
        headings,
        [
            "## Why a stateful key is dangerous",
            "## What a reused leaf leaks",
            "## One tree, one L",
            "## Rules for handling a key",
            "## What a production signing service needs",
            "## Glossary",
            "## Plain-language review",
        ],
        "{LMS_DOC}: sections in order"
    );
    let all = normalized(&doc);
    for needle in ["a leaf must never sign twice", "keys.md#stateful-lms-keys"] {
        assert!(all.contains(needle), "{LMS_DOC} must say `{needle}`");
    }
    for (heading, needles) in [
        (
            "Why a stateful key is dangerous",
            &["silent", "backup", "snapshot", "two CI runners", "retire"][..],
        ),
        (
            "What a reused leaf leaks",
            &["34 ladders", "checksum", "nobody can climb down", "HSS L=2"][..],
        ),
        (
            "One tree, one L",
            &[
                "u32str(L) || pub[0]",
                "u32str(1) || pub[0]",
                "u32str(2) || pub[0]",
                "never trust the same LMS tree at two different L values",
                "keelsign keygen",
                "--cnsa-2.0",
            ][..],
        ),
        (
            "Rules for handling a key",
            &[
                "Never sign with a copy",
                "keygen --force",
                "FILE.state",
                "FILE.journal",
                "One signer per key",
                "restored from a copy",
                "exit 10",
                "exit code 11",
                "LeafIndexExhausted",
                "retire the key",
                "public key",
                "SHA-319",
            ][..],
        ),
        (
            "What a production signing service needs",
            &[
                "strongly consistent",
                "Reserve, then sign",
                "SP 800-208, section 8.1",
                "Level 3",
                "section 7.1",
                "bottom tree",
                "Audit and alert",
                "SHA-308",
            ][..],
        ),
        (
            "Glossary",
            &[
                "**Leaf**",
                "**One-time signature",
                "**Tree**",
                "**Level (L)**",
                "**State file**",
                "**Journal**",
                "**HSM**",
                "**Strongly consistent**",
            ][..],
        ),
        (
            "Plain-language review",
            &["non-cryptographer", "Reviewed by:", "Pass:"][..],
        ),
    ] {
        let text = normalized(section(&doc, heading));
        for needle in needles {
            assert!(
                text.contains(needle),
                "{LMS_DOC} `## {heading}` must contain `{needle}`"
            );
        }
    }
    // The never rules come first, in one bulleted list.
    let rules = section(&doc, "Rules for handling a key");
    let nevers: Vec<&str> = rules
        .lines()
        .filter(|l| l.starts_with("- **Never"))
        .collect();
    assert_eq!(nevers.len(), 3, "{LMS_DOC}: the three never rules");
    // The rules live here only: keys.md points at them.
    let keys = read("docs/keys.md");
    assert!(
        !keys.contains("Rules for an LMS/HSS key:"),
        "docs/keys.md must point at docs/lms.md instead of repeating the rules"
    );
}

/// SHA-69 AC3: the README (its quickstart warning and its documentation list), keys.md,
/// signing.md and the CLI's stateful-key messages link docs/lms.md, and the anchor they
/// use exists.
#[test]
fn readme_keys_and_signing_docs_link_lms_doc() {
    let doc = read(LMS_DOC);
    assert!(
        doc.contains("\n## Rules for handling a key\n"),
        "the `rules-for-handling-a-key` anchor"
    );
    let readme = read("README.md");
    let quickstart = &readme[readme.find("## Quickstart").expect("quickstart")..];
    let warning = &quickstart[..quickstart.find("```sh").expect("quickstart block")];
    assert!(
        warning.contains("stateful") && warning.contains("(docs/lms.md#rules-for-handling-a-key)"),
        "the README quickstart warning links docs/lms.md#rules-for-handling-a-key"
    );
    let docs = &readme[readme.find("## Documentation").expect("documentation")..];
    assert!(
        docs.contains("[docs/lms.md](docs/lms.md)"),
        "the README documentation list links docs/lms.md"
    );
    for (file, link) in [
        ("docs/keys.md", "(lms.md#rules-for-handling-a-key)"),
        ("docs/signing.md", "(lms.md#rules-for-handling-a-key)"),
        (
            "keelsign/src/cli.rs",
            "docs/lms.md#rules-for-handling-a-key",
        ),
        (
            "keelsign/src/error.rs",
            "docs/lms.md#rules-for-handling-a-key",
        ),
    ] {
        assert!(read(file).contains(link), "{file} must link `{link}`");
    }
}

/// SHA-69 TP3 (NEEDS-HUMAN): a named non-cryptographer reviewed docs/lms.md for plain
/// language with the checklist in its `## Plain-language review` section, and the record
/// names the reviewer, the date and the changes. Ignored until the record is filled in.
#[test]
#[ignore = "NEEDS-HUMAN: fill the review record in docs/lms.md#plain-language-review"]
fn plain_language_review_is_recorded() {
    let doc = read(LMS_DOC);
    let review = section(&doc, "Plain-language review");
    let record = review
        .lines()
        .find(|l| l.starts_with("Reviewed by: "))
        .expect("a `Reviewed by:` line");
    assert!(
        !record.contains("(pending)") && !record.contains("(date)"),
        "the review record is still a placeholder: `{record}`"
    );
    assert!(
        record.contains(" on "),
        "the record names a date: `{record}`"
    );
    assert!(
        record.contains("changes: "),
        "the record lists the changes: `{record}`"
    );
}
