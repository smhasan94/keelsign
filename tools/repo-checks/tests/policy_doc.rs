//! Checks that docs/policy.md specifies the SHA-46 verify policies and that its matrix
//! table is exactly the `policy` cells of tests/fixtures/images/MANIFEST.json (which
//! keelsign-verify/tests/policy_matrix.rs and benches/policy-kat check against the code).

use repo_checks::{POLICY_KEYS, workspace_root};
use std::collections::BTreeMap;
use std::fs;

const REQUIRED_HEADINGS: [&str; 11] = [
    "# Verify policies (SHA-46)",
    "## Policies",
    "## Key sets",
    "## The `ed25519` feature",
    "## The `ml-dsa` feature",
    "## Image rules",
    "## Error precedence",
    "## Policy matrix",
    "## VerifiedImage and anti-rollback",
    "## TOCTOU",
    "## Differences from MCUboot",
];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn doc() -> String {
    read("docs/policy.md")
}

/// The text of the section starting at the heading line `heading`, up to the next heading
/// of the same or a higher level (headings inside code blocks are skipped).
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let level = heading.chars().take_while(|&c| c == '#').count();
    let start = doc
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("docs/policy.md has no `{heading}` heading"))
        + 1;
    let body = &doc[start + heading.len()..];
    let mut offset = 0;
    let mut in_code = false;
    for line in body.split_inclusive('\n') {
        if line.starts_with("```") {
            in_code = !in_code;
        }
        let hashes = line.chars().take_while(|&c| c == '#').count();
        if !in_code && hashes > 0 && hashes <= level && line[hashes..].starts_with(' ') {
            break;
        }
        offset += line.len();
    }
    &body[..offset]
}

/// The text of the JSON object stored under `"key": {` in `json` (brace-matched; the
/// manifest has no braces inside strings).
fn json_object<'a>(json: &'a str, key: &str) -> &'a str {
    let start = json
        .find(&format!("\"{key}\": {{"))
        .unwrap_or_else(|| panic!("MANIFEST.json has no object `{key}`"));
    let body = &json[start..];
    let open = body.find('{').expect("object opens");
    let mut depth = 0usize;
    for (i, c) in body[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[open..open + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated object `{key}`");
}

fn json_field<'a>(object: &'a str, field: &str) -> &'a str {
    let needle = format!("\"{field}\": ");
    let start = object
        .find(&needle)
        .unwrap_or_else(|| panic!("no field `{field}`"))
        + needle.len();
    let rest = &object[start..];
    let end = rest.find([',', '\n']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

/// Image name -> [ClassicalOnly, PqOnly, Hybrid] from MANIFEST.json.
fn manifest_cells() -> BTreeMap<String, Vec<String>> {
    manifest_cells_of("policy")
}

/// Image name -> the cells of the entry's object `object` (`policy`, or
/// `policy_without_ml_dsa` where the entry has it) from MANIFEST.json.
fn manifest_cells_of(object: &str) -> BTreeMap<String, Vec<String>> {
    let manifest = read("tests/fixtures/images/MANIFEST.json");
    let outputs = json_object(&manifest, "outputs");
    let mut cells = BTreeMap::new();
    for line in outputs.lines() {
        let Some(name) = line
            .strip_prefix("    \"")
            .and_then(|rest| rest.strip_suffix("\": {"))
        else {
            continue;
        };
        let entry = json_object(outputs, name);
        if !entry.contains(&format!("\"{object}\": {{")) {
            continue;
        }
        let policy = json_object(entry, object);
        let row = POLICY_KEYS
            .iter()
            .map(|key| json_field(policy, key).to_owned())
            .collect();
        cells.insert(name.to_owned(), row);
    }
    cells
}

/// Image name -> [ClassicalOnly, PqOnly, Hybrid] from the doc's matrix table (backticks
/// stripped).
fn doc_cells(doc: &str) -> BTreeMap<String, Vec<String>> {
    let matrix = section(doc, "## Policy matrix");
    let mut lines = matrix.lines().filter(|l| l.starts_with('|'));
    let header: Vec<String> = lines
        .next()
        .expect("matrix table")
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_owned())
        .collect();
    assert_eq!(
        header,
        ["Image", "ClassicalOnly", "PqOnly", "Hybrid", "Notes"],
        "matrix table columns"
    );
    let mut cells = BTreeMap::new();
    for line in lines.filter(|l| !l.starts_with("|---")) {
        let row: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        assert_eq!(row.len(), 5, "matrix row `{line}`");
        assert!(!row[4].is_empty(), "{}: Notes cell", row[0]);
        let previous = cells.insert(row[0].clone(), row[1..4].to_vec());
        assert!(previous.is_none(), "{} is listed twice", row[0]);
    }
    cells
}

#[test]
fn policy_doc_has_required_sections() {
    let doc = doc();
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with('#')).collect();
    for heading in REQUIRED_HEADINGS {
        assert!(
            headings.contains(&heading),
            "docs/policy.md is missing the heading `{heading}`"
        );
    }
    for term in [
        "verify_strict",
        "cmp_ignoring_build_num",
        "cmp_with_build_num",
        "MCUBOOT_VERSION_CMP_USE_BUILD_NUMBER",
        "`ed25519` feature",
        "NotEnabled",
        "with_ed25519",
        "keyhash_of",
        "key_id_of",
        "verify_with",
        "DefaultBackend::cnsa_2_0()",
        "security_counter",
        "prot = true",
        "image_validate.c:341-362",
        "image_validate.c:87-90",
        "image_validate.c:364-403",
        "bootutil_public.c:787",
        "image.h:191-198",
        "SHA-44",
        "0x4BA0..=0x4BAF",
        // SHA-44: the ml-dsa feature, the strict backend's refusal and the error mapping.
        "allows_ml_dsa",
        "`DefaultBackend::cnsa_2_0()` refuses ML-DSA",
        "MalformedSignature",
        "policy_without_ml_dsa",
        "MLDSA_CONTEXT",
        "SHA-169",
    ] {
        assert!(doc.contains(term), "docs/policy.md must mention `{term}`");
    }
    let policies = section(&doc, "## Policies");
    for policy in ["`ClassicalOnly`", "`PqOnly`", "`Hybrid`", "no default"] {
        assert!(
            policies.contains(policy),
            "## Policies must mention {policy}"
        );
    }
    let toctou = section(&doc, "## TOCTOU");
    assert!(toctou.contains("parsed copy") && toctou.contains("body"));
    // The doc links the format, and the format and the benchmarks link back.
    assert!(doc.contains("(image-format.md)"));
    assert!(read("docs/image-format.md").contains("(policy.md)"));
    assert!(doc.contains("benchmarks.md#hybrid-verify-entry-point-sha-46"));
}

#[test]
fn matrix_table_matches_manifest() {
    let manifest = manifest_cells();
    let doc = doc_cells(&doc());
    assert_eq!(manifest.len(), 53, "every MANIFEST.json output");
    let doc_names: Vec<&String> = doc.keys().collect();
    let manifest_names: Vec<&String> = manifest.keys().collect();
    assert_eq!(
        doc_names, manifest_names,
        "matrix rows == MANIFEST.json outputs"
    );
    for (name, cells) in &manifest {
        assert_eq!(
            &doc[name], cells,
            "{name}: doc cells != MANIFEST.json policy cells"
        );
    }
}

/// SHA-44: the `ml-dsa` section's table is exactly the manifest's `policy_without_ml_dsa`
/// cells (the cells that differ without the feature).
#[test]
fn ml_dsa_off_table_matches_manifest() {
    let doc = doc();
    let section = section(&doc, "## The `ml-dsa` feature");
    let mut lines = section
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('|'));
    let header: Vec<String> = lines
        .next()
        .expect("off-cells table")
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_owned())
        .collect();
    assert_eq!(header, ["Image", "ClassicalOnly", "PqOnly", "Hybrid"]);
    let mut table = BTreeMap::new();
    for line in lines {
        if line.starts_with("|---") {
            continue;
        }
        let row: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        // The error-mapping table follows; it has two columns.
        if row.len() != 4 {
            break;
        }
        assert!(table.insert(row[0].clone(), row[1..4].to_vec()).is_none());
    }
    let manifest = manifest_cells_of("policy_without_ml_dsa");
    assert_eq!(manifest.len(), 17, "the ML-DSA images whose cells change");
    assert_eq!(
        table, manifest,
        "## The `ml-dsa` feature table != MANIFEST.json"
    );
    // Each differing cell is UnsupportedAlgorithm of the image's set.
    let on = manifest_cells();
    for (name, off) in &manifest {
        for (i, cell) in off.iter().enumerate() {
            if *cell != on[name][i] {
                assert!(
                    cell.starts_with("UnsupportedAlgorithm(MlDsa"),
                    "{name}: {cell}"
                );
            }
        }
    }
}

/// The variant names of `pub enum {name}` in `src` (one per line, before `(` or `,`).
fn enum_variants(src: &str, name: &str) -> Vec<String> {
    let start = src
        .find(&format!("pub enum {name} {{"))
        .unwrap_or_else(|| panic!("no `pub enum {name}`"));
    let body = &src[start..];
    let body = &body[body.find('{').unwrap() + 1..body.find("\n}").unwrap()];
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#'))
        .map(|l| l.split(['(', ',']).next().unwrap().trim().to_owned())
        .collect()
}

#[test]
fn doc_names_every_error_variant() {
    let doc = doc();
    let error = enum_variants(&read("keelsign-verify/src/error.rs"), "Error");
    let image = enum_variants(&read("keelsign-verify/src/policy.rs"), "ImageError");
    let ed25519 = enum_variants(&read("keelsign-verify/src/ed25519.rs"), "Ed25519Error");
    assert_eq!(error.len(), 18, "{error:?}");
    assert_eq!(image.len(), 11, "{image:?}");
    assert_eq!(ed25519.len(), 9, "{ed25519:?}");
    for name in error.iter().chain(&image).chain(&ed25519) {
        assert!(
            doc.contains(name.as_str()),
            "docs/policy.md must name `{name}`"
        );
    }
    // The precedence list is numbered 1..=11 and names the errors in the order
    // `verify_with` checks them.
    let precedence = section(&doc, "## Error precedence");
    let mut at = 0;
    for n in 1..=11 {
        let item = format!("\n{n}. ");
        let found = precedence[at..]
            .find(&item)
            .unwrap_or_else(|| panic!("precedence item {n} missing or out of order"));
        at += found + item.len();
    }
    let mut order: Vec<String> = Vec::from(["Ed25519(NotEnabled)".to_owned()]);
    order.extend(["Parse(_)", "Read(_)", "TlvAreaTooLarge"].map(str::to_owned));
    order.extend(
        [
            "Encrypted",
            "Compressed",
            "NonBootable",
            "KeelsignTlvProtected(_)",
            "SigPure",
            "MissingSha256Tlv",
            "MultipleSha256Tlvs",
            "InvalidSha256Tlv",
            "MultipleSecurityCounters",
            "InvalidSecurityCounter",
        ]
        .map(|v| format!("Image({v})")),
    );
    order.push("ChunkBufferEmpty".to_owned());
    order.push("Image(DigestMismatch)".to_owned());
    order.extend(
        ed25519
            .iter()
            .filter(|v| *v != "NotEnabled")
            .map(|v| format!("Ed25519({v})")),
    );
    order.extend(
        [
            "MultipleKeyIds",
            "MultiplePqSignatures",
            "MissingPqSignature",
            "MissingKeyId",
            "InvalidKeyId",
            "KeyNotTrusted",
            "KeyAlgorithmMismatch",
            "UnsupportedAlgorithm(_)",
            "UnsupportedParameterSet",
            "MalformedSignature",
            "InvalidPublicKey",
            "SignatureInvalid",
        ]
        .map(str::to_owned),
    );
    order.push("Ok(VerifiedImage)".to_owned());
    // Every ImageError variant is in the order.
    for v in &image {
        assert!(
            order.iter().any(|o| o.starts_with(&format!("Image({v}"))),
            "precedence order misses Image({v})"
        );
    }
    let mut last = 0;
    for token in &order {
        let needle = format!("`{token}`");
        let pos = precedence[last..]
            .find(&needle)
            .unwrap_or_else(|| panic!("## Error precedence: `{token}` missing or out of order"));
        last += pos + needle.len();
    }
    // policy.rs documents the same precedence in its rustdoc.
    let src = read("keelsign-verify/src/policy.rs");
    assert!(src.contains("//! # Error precedence"));
}
