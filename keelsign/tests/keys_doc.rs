//! docs/keys.md documents the OIDs and file formats keelsign actually writes (SHA-49
//! AC2).

use keelsign::keys::{
    ID_ED25519, ID_ML_DSA_44, ID_ML_DSA_65, PEM_ENCRYPTED_PRIVATE_KEY, PEM_PRIVATE_KEY,
    PEM_PUBLIC_KEY,
};
use std::path::Path;

#[test]
fn docs_keys_md_lists_the_oids_and_formats() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/keys.md");
    let doc = std::fs::read_to_string(&path).expect("read docs/keys.md");

    for heading in [
        "## Commands",
        "## Algorithms and OIDs",
        "## Private key files",
        "## Public key files",
        "## Passphrase encryption",
        "## Key ID and KEYHASH",
        "## File permissions and overwriting",
        "## Exit codes",
        "## Checking a key file",
    ] {
        assert!(
            doc.lines().any(|l| l == heading),
            "docs/keys.md lacks `{heading}`"
        );
    }

    // The OID table: the OIDs the code uses, with their names and sources.
    for (oid, name) in [
        (ID_ML_DSA_44, "id-ml-dsa-44"),
        (ID_ML_DSA_65, "id-ml-dsa-65"),
        (ID_ED25519, "id-Ed25519"),
    ] {
        let row = doc
            .lines()
            .find(|l| l.starts_with('|') && l.contains(&format!("`{oid}`")))
            .unwrap_or_else(|| panic!("docs/keys.md has no table row for {oid}"));
        assert!(row.contains(name), "row for {oid} names {name}: {row}");
    }
    for needle in [
        "sigAlgs 17",
        "sigAlgs 18",
        "RFC 9881 §2",
        "RFC 8410 §3",
        "parameters",
        // Private key files.
        PEM_PRIVATE_KEY,
        PEM_ENCRYPTED_PRIVATE_KEY,
        PEM_PUBLIC_KEY,
        "PKCS#8",
        "version 1",
        "RFC 9881 §6",
        "seed [0] IMPLICIT OCTET STRING (SIZE (32))",
        "30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20",
        "ml-dsa.output_formats=seed-only",
        // Public key files.
        "SubjectPublicKeyInfo",
        "30820532300b06096086480165030403110382052100",
        "308207b2300b0609608648016503040312038207a100",
        "302a300506032b6570032100",
        // Passphrase encryption.
        "1.2.840.113549.1.5.13",
        "1.3.6.1.4.1.11591.4.11",
        "2.16.840.1.101.3.4.1.42",
        "N = 16384",
        "r = 8",
        "p = 1",
        "16-byte salt",
        "--passphrase-file",
        "--passphrase-env",
        "2^20",
        "10,000,000",
        "unsupported encryption scheme",
        "zeroizing buffers",
        ".NAME.keelsign-tmp-PID",
        // Key ID and KEYHASH, with the RFC worked examples.
        "image-format.md#key-id",
        "9f107644c1084526af3bc8098680b054",
        "d666806e11cee19a7c989f7445f90dd4",
        "a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f",
        // Permissions and overwriting.
        "`0600`",
        "--force",
        // Checking a key file.
        "openssl asn1parse",
        "openssl pkey",
        "imgtool getpub",
        "imgtool getpubhash",
    ] {
        assert!(doc.contains(needle), "docs/keys.md lacks `{needle}`");
    }

    // One exit-code row per code 0..=6.
    for code in 0..=6 {
        assert!(
            doc.lines().any(|l| l.starts_with(&format!("| {code} |"))),
            "docs/keys.md has no exit-code row for {code}"
        );
    }
}
