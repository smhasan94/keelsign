//! docs/signing.md documents the commands, the TLVs `sign` adds, the inspect JSON schema
//! and its stability policy, and the exit codes keelsign uses (SHA-51 AC3).

use keelsign_verify::tlv::{
    MLDSA_CONTEXT, TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG, TLV_MLDSA65_SIG,
};
use std::path::Path;

fn doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/signing.md");
    std::fs::read_to_string(&path).expect("read docs/signing.md")
}

#[test]
fn signing_md_documents_inspect_schema_and_stability_policy() {
    let doc = doc();
    for heading in [
        "## Commands",
        "## What sign adds",
        "## What is preserved",
        "## The image digest M",
        "## Hedged ML-DSA signing",
        "## Self-check",
        "## Refusals",
        "## Hybrid images",
        "## inspect",
        "## JSON schema and stability",
        "## Exit codes",
        "## Interoperability checks",
        "## LMS/HSS",
    ] {
        assert!(
            doc.lines().any(|l| l == heading),
            "docs/signing.md lacks `{heading}`"
        );
    }

    let context = std::str::from_utf8(MLDSA_CONTEXT).expect("ASCII context");
    let tlv_ids = [
        TLV_KEELSIGN_KEY_ID,
        TLV_MLDSA44_SIG,
        TLV_MLDSA65_SIG,
        TLV_LMS_HSS_SIG,
    ]
    .map(|t| format!("`{t:#06X}`").replace("0X", "0x"));
    for needle in [
        // Commands and options.
        "keelsign sign --key FILE [--hybrid-key FILE] [--replace] [--force]",
        "keelsign inspect [--json] IMAGE",
        "--passphrase-file",
        "--passphrase-env",
        // What sign adds, in order, and the signing mode.
        "| 1 | `KEYHASH` | `0x01`",
        "| 2 | `ED25519` | `0x24`",
        "| 3 | keelsign key ID |",
        "| 4 | ML-DSA-44 / ML-DSA-65 signature |",
        "2,420 / 3,309 bytes",
        context,
        "hedged",
        "keelsign_verify::verify",
        "byte for byte",
        // Refusals.
        "sign before padding; padded images are a follow-up",
        "0x4BA0..=0x4BAF",
        // The schema and its stability policy.
        "docs/inspect-schema.json",
        "Draft 2020-12",
        "additionalProperties: false",
        "`schema_version` is `1`",
        "Fields are never removed, renamed or retyped.",
        "New fields are optional, and the schema is updated in the same change that adds them.",
        "A breaking change bumps `schema_version`.",
        "scripts/gen_inspect_snapshots.py",
        // Interop.
        "imgtool==2.4.0",
        "cargo test -p keelsign --locked --test imgtool -- --ignored",
        "imgtool dumpinfo",
        "imgtool verify",
        // Pointers.
        "SHA-53",
        "E7.2",
    ] {
        assert!(doc.contains(needle), "docs/signing.md lacks `{needle}`");
    }
    for id in &tlv_ids[..3] {
        assert!(doc.contains(id.as_str()), "docs/signing.md lacks {id}");
    }
    assert!(
        doc.contains(&tlv_ids[3]),
        "docs/signing.md names the LMS/HSS TLV"
    );
    assert_eq!(keelsign::inspect::SCHEMA_VERSION, 1);
    assert!(doc.contains(&format!("`format` is `\"{}\"`", keelsign::inspect::FORMAT)));

    // One exit-code row per code 0..=9.
    for code in 0..=9 {
        assert!(
            doc.lines().any(|l| l.starts_with(&format!("| {code} |"))),
            "docs/signing.md has no exit-code row for {code}"
        );
    }
}
