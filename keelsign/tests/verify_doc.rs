//! docs/verify.md documents `keelsign verify`: the command, the public key files it reads
//! (with the four OIDs), the policies and their inference, what is checked, the output,
//! CNSA 2.0, and the final exit-code table (SHA-53).

use keelsign::keys::{ID_ED25519, ID_HSS_LMS_HASHSIG, ID_ML_DSA_44, ID_ML_DSA_65};
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `| N | meaning |` rows of the `## Exit codes` section of `doc`.
fn exit_rows(doc: &str) -> Vec<(u8, String)> {
    let section = doc
        .split("\n## Exit codes\n")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("an `## Exit codes` section");
    section
        .lines()
        .filter_map(|l| l.strip_prefix("| "))
        .filter_map(|l| l.split_once(" | "))
        .filter_map(|(code, meaning)| Some((code.parse().ok()?, meaning.to_owned())))
        .collect()
}

#[test]
fn verify_md_documents_the_final_exit_code_table() {
    let doc = read("docs/verify.md");
    for heading in [
        "## Commands",
        "## Public key files",
        "## Policies and inference",
        "## What is checked",
        "## Output",
        "## Tampering",
        "## Padded images",
        "## Key rotation",
        "## CNSA 2.0",
        "## Exit codes",
        "## imgtool interoperability",
    ] {
        assert!(
            doc.lines().any(|l| l == heading),
            "docs/verify.md lacks `{heading}`"
        );
    }
    for oid in [ID_ML_DSA_44, ID_ML_DSA_65, ID_ED25519, ID_HSS_LMS_HASHSIG] {
        assert!(
            doc.contains(&format!("`{oid}`")),
            "docs/verify.md names the OID {oid}"
        );
    }
    for needle in [
        "keelsign verify --pub FILE [--pub FILE ...] [--policy classical|pq|hybrid] [--cnsa-2.0] IMAGE",
        "RFC 8708",
        "RFC 5912",
        "`PUBLIC-KEY` convention",
        "imgtool getpub -e pem",
        "up to 8 post-quantum keys",
        "(inferred from the keys given)",
        "keelsign_verify::verify_with",
        "DefaultBackend::cnsa_2_0()",
        "single-tree LMS only",
        "trailing bytes ignored",
        "not verified under policy",
        "no ED25519 signature TLV",
        "MANIFEST.json",
        "`ChunkBufferEmpty`",
        "The table is final",
    ] {
        assert!(doc.contains(needle), "docs/verify.md lacks `{needle}`");
    }

    // The final table: one row per code 0..=9, the same codes as docs/keys.md and
    // docs/signing.md, and the meanings keelsign/src/error.rs gives the new code.
    let rows = exit_rows(&doc);
    let codes: Vec<u8> = rows.iter().map(|(c, _)| *c).collect();
    assert_eq!(
        codes,
        (0..=9).collect::<Vec<u8>>(),
        "docs/verify.md exit codes"
    );
    for other in ["docs/keys.md", "docs/signing.md"] {
        let other_codes: Vec<u8> = exit_rows(&read(other)).iter().map(|(c, _)| *c).collect();
        assert_eq!(other_codes, codes, "{other} exit codes");
    }
    let meaning = |code: u8| {
        rows.iter()
            .find(|(c, _)| *c == code)
            .map(|(_, m)| m.as_str())
            .expect("row")
    };
    assert!(meaning(9).starts_with("`verify`: the image is not verified under the policy"));
    assert!(meaning(7).contains("malformed"));
    assert!(meaning(2).contains("no `--pub`"));
    assert!(meaning(5).contains("a private key"));
    assert!(meaning(1).contains("`--pub` file"));
    let error_rs = read("keelsign/src/error.rs");
    assert!(error_rs.contains("//! | 9 | `verify`: the image is not verified under the policy"));
    assert!(error_rs.contains("Self::NotVerified { .. } => 9,"));
    assert!(
        !error_rs.contains("provisional"),
        "error.rs: the table is final"
    );
    assert!(!read("docs/signing.md").contains("provisional"));
}
