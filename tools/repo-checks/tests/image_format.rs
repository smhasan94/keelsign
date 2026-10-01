//! Checks that docs/image-format.md specifies the keelsign image format (SHA-37) and
//! agrees with keelsign-verify/src/tlv.rs, and that the sample images in
//! tests/fixtures/images/ are script-generated and match their manifest.

use repo_checks::{IMAGE_FIXTURES, python_script, run_capture, sha256_hex, workspace_root};
use std::fs;

const REQUIRED_HEADINGS: [&str; 14] = [
    "# keelsign image format (SHA-37)",
    "## TLV table",
    "## Signing mode",
    "### Rationale",
    "## Key ID",
    "## Hybrid layout",
    "## One PQ signature per image",
    "## Sizes",
    "## ML-DSA context",
    "## Accepted LMS parameter sets and CNSA 2.0",
    "## MCUboot compatibility",
    "## MCUboot compatibility checklist",
    "## Out of scope",
    "## References",
];

/// Commits the checklist may cite: MCUboot, nrfconnect/sdk-mcuboot, nrfconnect/sdk-nrf.
const PINNED_COMMITS: [(&str, &str); 3] = [
    ("a8ffd2c", "a8ffd2c312910cc648219bcb29e04260f7857492"),
    ("2b21b8b", "2b21b8b1bd3e93b0538dd50768dab71b8836ac25"),
    ("8270993", "8270993e2405c973d083a8d04713bd5b9b38fc09"),
];

/// FIPS 204 Table 2: (name, public key, signature) bytes.
const MLDSA: [(&str, u64, u64); 2] = [("ML-DSA-44", 1312, 2420), ("ML-DSA-65", 1952, 3309)];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn doc() -> String {
    read("docs/image-format.md")
}

fn tlv_rs() -> String {
    read("keelsign-verify/src/tlv.rs")
}

/// The text of the section starting at the heading line `heading`, up to the next heading
/// of the same or a higher level.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let level = heading.chars().take_while(|&c| c == '#').count();
    let start = doc
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("docs/image-format.md has no `{heading}` heading"))
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

/// The markdown tables in `text`, each as its rows of cells (header and separator rows
/// excluded).
fn tables(text: &str) -> Vec<Vec<Vec<String>>> {
    let mut out: Vec<Vec<Vec<String>>> = Vec::new();
    let mut current: Option<Vec<Vec<String>>> = None;
    let mut header_seen = false;
    for line in text.lines() {
        if line.starts_with('|') {
            let table = current.get_or_insert_with(Vec::new);
            if !header_seen {
                header_seen = true;
            } else if !line.starts_with("|---") {
                table.push(
                    line.trim_matches('|')
                        .split('|')
                        .map(|c| c.trim().to_owned())
                        .collect(),
                );
            }
        } else if let Some(table) = current.take() {
            out.push(table);
            header_seen = false;
        }
    }
    out.extend(current);
    out
}

/// A number cell such as `3,924` or `2,420`.
fn parse_number(cell: &str) -> Option<u64> {
    cell.replace(',', "").trim().parse().ok()
}

/// The value of `pub const NAME: TYPE = VALUE;` in tlv.rs, as written.
fn const_value<'a>(src: &'a str, name: &str) -> &'a str {
    let needle = format!("pub const {name}: ");
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("tlv.rs has no `{name}`"));
    let rest = &src[start + needle.len()..];
    let eq = rest.find(" = ").expect("`=`") + 3;
    let end = rest.find(';').expect("`;`");
    &rest[eq..end]
}

fn parse_hex(text: &str) -> u16 {
    u16::from_str_radix(text.trim().trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("not a hex u16 `{text}`: {e}"))
}

/// The four assigned TLV constants of tlv.rs as (name, value).
fn tlv_ids(src: &str) -> Vec<(&'static str, u16)> {
    [
        "TLV_KEELSIGN_KEY_ID",
        "TLV_MLDSA44_SIG",
        "TLV_MLDSA65_SIG",
        "TLV_LMS_HSS_SIG",
    ]
    .into_iter()
    .map(|name| (name, parse_hex(const_value(src, name))))
    .collect()
}

/// HSS signature bytes with LM-OTS W8, hash length `m` (= n), per-level heights `hs`
/// (RFC 8554 §4.5, §5.4, §6.2; p = 34 for n = 32 and 26 for n = 24).
fn hss_w8_len(m: u64, hs: &[u64]) -> u64 {
    let p = match m {
        32 => 34,
        24 => 26,
        _ => panic!("unsupported m = {m}"),
    };
    let lms = |h: u64| 4 + (4 + m + p * m) + 4 + h * m;
    let levels = hs.len() as u64;
    4 + hs.iter().map(|&h| lms(h)).sum::<u64>() + (levels - 1) * (4 + 4 + 16 + m)
}

#[test]
fn doc_has_required_sections() {
    let doc = doc();
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with('#')).collect();
    for heading in REQUIRED_HEADINGS {
        assert!(
            headings.contains(&heading),
            "docs/image-format.md is missing the heading `{heading}`"
        );
    }
    let signing = section(&doc, "## Signing mode");
    for term in [
        "SHA-256",
        "protected TLV area",
        "IMAGE_TLV_SHA256",
        "ML-DSA",
        "LMS/HSS",
        "HashML-DSA",
        "IMAGE_TLV_SIG_PURE",
        "SHA-42",
        "SHA-46",
    ] {
        assert!(
            signing.contains(term),
            "## Signing mode must mention `{term}`"
        );
    }
    assert!(!section(&doc, "### Rationale").trim().is_empty());
    let lms = section(&doc, "## Accepted LMS parameter sets and CNSA 2.0");
    for term in [
        "cnsa_2_0()",
        "keelsign_default()",
        "DefaultBackend::cnsa_2_0()",
        "verify_pq_with",
        "CNSA 2.0 FAQ v2.1",
        "Deviation from CNSA 2.0",
        "L = 1",
        "are not allowed",
        "web.archive.org",
    ] {
        assert!(
            lms.contains(term),
            "the LMS/CNSA section must mention `{term}`"
        );
    }
    // SHA-240 implemented the split: the section no longer describes it as planned.
    assert!(
        !lms.contains("planned"),
        "the LMS/CNSA section must not describe the policy split as planned"
    );
    let compat = section(&doc, "## MCUboot compatibility");
    for term in [
        "CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST",
        "SHA-62",
        "#2707",
        "0x26",
    ] {
        assert!(
            compat.contains(term),
            "## MCUboot compatibility must mention `{term}`"
        );
    }
    let out = section(&doc, "## Out of scope");
    for term in [
        "format-version TLV",
        "policy TLV",
        "parameter-set TLV",
        "ML-DSA-87",
        "SLH-DSA",
    ] {
        assert!(out.contains(term), "## Out of scope must list `{term}`");
    }
    let references = section(&doc, "## References");
    for (_, full) in PINNED_COMMITS {
        assert!(references.contains(full), "## References must pin {full}");
    }
}

#[test]
fn doc_tlv_table_matches_tlv_rs() {
    let doc = doc();
    let src = tlv_rs();
    let table = section(&doc, "## TLV table");
    let rows = &tables(table)[0];
    let ids = tlv_ids(&src);
    assert_eq!(
        rows.len(),
        ids.len() + 1,
        "four assigned IDs and the reserved row"
    );
    for (name, value) in &ids {
        let id = format!("`{value:#06X}`").replace("0X", "0x");
        let row = rows
            .iter()
            .find(|r| r[0] == id)
            .unwrap_or_else(|| panic!("TLV table has no row {id}"));
        assert_eq!(row[1], format!("`{name}`"), "{id}");
        assert_eq!(row[4], "unprotected", "{id}: area");
    }
    let key_id_len = const_value(&src, "KEY_ID_LEN");
    assert!(rows[0][2].starts_with(key_id_len), "key-ID length cell");
    assert!(rows[1][2] == "2,420" && rows[2][2] == "3,309");

    // The keelsign block and the reserved rest of it.
    let range = const_value(&src, "KEELSIGN_TLV_RANGE");
    let (start, end) = range.split_once("..=").expect("inclusive range");
    let (start, end) = (parse_hex(start), parse_hex(end));
    assert_eq!((start, end), (0x4BA0, 0x4BAF));
    for (name, value) in &ids {
        assert!((start..=end).contains(value), "{name} outside the block");
    }
    let max_assigned = ids.iter().map(|(_, v)| *v).max().unwrap();
    let reserved = format!("`{:#06X}`–`{:#06X}`", max_assigned + 1, end).replace("0X", "0x");
    let reserved_row = rows.last().unwrap();
    assert_eq!(reserved_row[0], reserved);
    assert_eq!(reserved_row[1], "reserved");
    assert!(table.contains(&format!("`{start:#06X}`–`{end:#06X}`").replace("0X", "0x")));
    assert!(table.contains("`KEELSIGN_TLV_RANGE`"));
    assert!(table.contains("MUST ignore"));

    // The ML-DSA context string, byte for byte.
    let context = const_value(&src, "MLDSA_CONTEXT");
    assert_eq!(context, "b\"keelsign-mcuboot-image-v1\"");
    let doc_context = section(&doc, "## ML-DSA context");
    assert!(
        doc_context.contains(&format!("MLDSA_CONTEXT = {context}")),
        "## ML-DSA context must state `MLDSA_CONTEXT = {context}`"
    );
    assert!(doc_context.contains("(25 bytes)"));
}

#[test]
fn tlv_rs_has_no_provisional_and_links_spec() {
    let src_dir = workspace_root().join("keelsign-verify/src");
    for entry in fs::read_dir(&src_dir).expect("read keelsign-verify/src") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("read source");
            assert!(
                !text.to_lowercase().contains("provisional"),
                "{} must not call anything provisional",
                path.display()
            );
        }
    }
    let src = tlv_rs();
    let spec = "https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md";
    assert!(src.contains(spec), "tlv.rs module docs link the spec");
    // Every public constant's doc comment links the spec.
    let lines: Vec<&str> = src.lines().collect();
    let mut constants = 0;
    for (i, line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix("pub const ") {
            let name = rest.split(':').next().unwrap();
            let docs: Vec<&str> = lines[..i]
                .iter()
                .rev()
                .take_while(|l| l.starts_with("///"))
                .copied()
                .collect();
            assert!(
                docs.iter().any(|l| l.contains(spec)),
                "doc comment of `{name}` must link {spec}"
            );
            constants += 1;
        }
    }
    assert_eq!(
        constants, 8,
        "four TLV IDs, the range, KEY_ID_LEN, context, max length"
    );
    for rel in [
        "keelsign-verify/src/lib.rs",
        "keelsign-verify/src/trusted_keys.rs",
        "keelsign-verify/src/dispatch.rs",
        "keelsign-verify/README.md",
        "README.md",
    ] {
        assert!(
            read(rel).contains("docs/image-format.md"),
            "{rel} must link docs/image-format.md"
        );
    }
    // No hard-coded old provisional ID remains in the code that uses the constants.
    for rel in [
        "keelsign-verify/src/algorithm.rs",
        "keelsign-verify/src/backend.rs",
        "benches/lms-kat/src/lib.rs",
    ] {
        let text = read(rel);
        for old in ["0x00A0", "0x00A1", "0x00A2", "0x00A3"] {
            assert!(!text.contains(old), "{rel} hard-codes the old ID {old}");
        }
    }
}

#[test]
fn sizes_table_matches_lms_formula_and_mldsa_constants() {
    let doc = doc();
    let src = tlv_rs();
    let sizes = section(&doc, "## Sizes");
    let tables = tables(sizes);
    assert_eq!(
        tables.len(),
        2,
        "## Sizes has the size table and the TLV-area table"
    );
    let (rows, area) = (&tables[0], &tables[1]);

    let mut max = 0;
    let mut lms_rows = 0;
    for row in rows {
        let bytes = parse_number(&row[3]).unwrap_or_else(|| panic!("bytes cell {row:?}"));
        match row[0].as_str() {
            "Key ID" => {
                assert_eq!(bytes.to_string(), const_value(&src, "KEY_ID_LEN"));
                continue;
            }
            "LMS/HSS" => {
                // `M32 H10+H10`
                let (m, heights) = row[1].split_once(' ').expect("`M.. H..`");
                let m: u64 = m.trim_start_matches('M').parse().expect("m");
                let hs: Vec<u64> = heights
                    .split('+')
                    .map(|h| h.trim_start_matches('H').parse().expect("h"))
                    .collect();
                assert_eq!(row[2], hs.len().to_string(), "{row:?}: levels");
                assert_eq!(bytes, hss_w8_len(m, &hs), "{row:?}");
                lms_rows += 1;
            }
            name => {
                let (_, _, sig) = MLDSA
                    .iter()
                    .find(|(n, _, _)| *n == name)
                    .unwrap_or_else(|| panic!("unknown size row {row:?}"));
                assert_eq!(bytes, *sig, "{name}");
            }
        }
        max = max.max(bytes);
    }
    assert_eq!(lms_rows, 12, "m 24/32 x H10/H20/H25 x L1/L2");
    assert!(rows.iter().any(|r| r[0] == "ML-DSA-44") && rows.iter().any(|r| r[0] == "ML-DSA-65"));
    let max_const: u64 = const_value(&src, "MAX_PQ_SIGNATURE_LEN")
        .replace('_', "")
        .parse()
        .expect("MAX_PQ_SIGNATURE_LEN");
    assert_eq!(
        max, max_const,
        "MAX_PQ_SIGNATURE_LEN is the table's largest row"
    );
    assert_eq!(max_const, hss_w8_len(32, &[25, 25]));

    // The ML-DSA constants of keelsign-verify agree with FIPS 204.
    let algorithm = read("keelsign-verify/src/algorithm.rs");
    for (name, pk, sig) in MLDSA {
        assert!(
            algorithm.contains(&format!("Some({pk})")),
            "algorithm.rs: {name} public key {pk}"
        );
        let sig = format!("{},{:03}", sig / 1000, sig % 1000);
        assert!(
            src.contains(&sig),
            "tlv.rs documents the {name} signature ({sig})"
        );
    }

    // Worst-case hybrid unprotected TLV area: info + SHA256 + KEYHASH + ED25519 + key ID
    // + PQ signature.
    let expected = 4 + (4 + 32) + (4 + 32) + (4 + 64) + (4 + 16) + (4 + max_const);
    let parts: Vec<u64> = area[..area.len() - 1]
        .iter()
        .map(|r| parse_number(&r[1]).unwrap_or_else(|| panic!("{r:?}")))
        .collect();
    assert_eq!(parts.iter().sum::<u64>(), expected);
    let total = area.last().unwrap();
    assert_eq!(total[0], "Total");
    assert_eq!(parse_number(&total[1]), Some(expected));
    assert!(expected <= 4096, "fits the one-page budget");
    assert!(sizes.contains(&format!("leaves {} bytes", 4096 - expected)));
    assert!(sizes.contains("SHA-58"));
}

#[test]
fn checklist_rows_all_ticked_and_cite_sources() {
    let doc = doc();
    let checklist = section(&doc, "## MCUboot compatibility checklist");
    // Items start with `- [`; continuation lines are indented.
    let mut items: Vec<String> = Vec::new();
    for line in checklist.lines() {
        if line.starts_with("- [") {
            items.push(line.to_owned());
        } else if line.starts_with("  ")
            && let Some(last) = items.last_mut()
        {
            last.push(' ');
            last.push_str(line.trim());
        }
    }
    assert!(items.len() >= 12, "checklist has {} rows", items.len());
    for item in &items {
        assert!(
            item.starts_with("- [x] "),
            "checklist row not ticked: {item}"
        );
        // A backticked `path:line` or `:line` citation.
        let cites_line = item.split('`').skip(1).step_by(2).any(|code| {
            code.rsplit_once(':').is_some_and(|(_, lines)| {
                !lines.is_empty() && lines.chars().all(|c| c.is_ascii_digit() || c == '-')
            })
        });
        assert!(cites_line, "checklist row cites no file:line: {item}");
        assert!(
            PINNED_COMMITS
                .iter()
                .any(|(short, _)| item.contains(&format!("@ `{short}`"))),
            "checklist row names no pinned commit: {item}"
        );
    }
    assert!(!checklist.contains("- [ ]"));
}

// ---- Sample images ----------------------------------------------------------------------

fn image_manifest() -> String {
    read("tests/fixtures/images/MANIFEST.json")
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

/// A scalar field of a JSON object (`"field": value`), without quotes.
fn json_field<'a>(object: &'a str, field: &str) -> &'a str {
    let needle = format!("\"{field}\": ");
    let start = object
        .find(&needle)
        .unwrap_or_else(|| panic!("no field `{field}` in {object:.80}"))
        + needle.len();
    let rest = &object[start..];
    let end = rest.find([',', '\n']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

/// Standard base64 (RFC 4648 section 4), padding and surrounding whitespace allowed.
fn base64_decode(text: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for &c in text
        .iter()
        .filter(|c| !c.is_ascii_whitespace() && **c != b'=')
    {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("not base64: {c:#04x}"));
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[test]
fn image_fixtures_match_manifest() {
    let manifest = image_manifest();
    let outputs = json_object(&manifest, "outputs");
    let keys = json_object(&manifest, "keys");
    let dir = workspace_root().join("tests/fixtures/images");
    let signatures = json_object(&manifest, "signatures");
    for name in IMAGE_FIXTURES {
        let path = dir.join(name);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let entry = if name.starts_with("keys/") {
            if name.ends_with(".pem") {
                assert!(
                    bytes.starts_with(b"# TEST KEY"),
                    "{name}: a committed key must start with `# TEST KEY`"
                );
            }
            json_object(keys, name)
        } else if name.starts_with("sigs/") {
            // Fixed classical signatures (imgtool --sig-out), base64: RSA-2048 PSS is 256
            // bytes, a DER ECDSA P-256 signature 70 to 72.
            let decoded = base64_decode(&bytes);
            let expected = if name.contains("rsa2048") {
                256..=256
            } else {
                assert!(name.contains("ecdsa-p256"), "{name}: unknown signature");
                70..=72
            };
            assert!(
                expected.contains(&decoded.len()),
                "{name}: {} decoded bytes",
                decoded.len()
            );
            let entry = json_object(signatures, name);
            assert_eq!(
                decoded.len().to_string(),
                json_field(entry, "decoded_bytes")
            );
            entry
        } else {
            let entry = json_object(outputs, name);
            assert_eq!(
                bytes.len().to_string(),
                json_field(entry, "bytes"),
                "{name}: size"
            );
            if name.starts_with("rejected/") {
                // Rejected images say why; the big-endian one has the magic byte-swapped.
                assert_ne!(json_field(entry, "expect_parse"), "Ok", "{name}");
                if json_field(entry, "endian") == "big" {
                    assert_eq!(&bytes[..4], &[0x96, 0xf3, 0xb8, 0x3d], "{name}: magic");
                }
            } else {
                // MCUboot image magic, little-endian.
                assert_eq!(&bytes[..4], &[0x3d, 0xb8, 0xf3, 0x96], "{name}: magic");
                assert_eq!(json_field(entry, "expect_parse"), "Ok", "{name}");
            }
            entry
        };
        assert_eq!(
            sha256_hex(&bytes),
            json_field(entry, "sha256"),
            "{name}: sha256 differs from MANIFEST.json; regenerate with scripts/gen_image_fixtures.py"
        );
    }
    assert_eq!(
        outputs.matches("\"sha256\":").count(),
        IMAGE_FIXTURES
            .iter()
            .filter(|n| n.ends_with(".bin"))
            .count(),
        "MANIFEST.json lists exactly the fixture images"
    );
    // SHA-42: the 200 KB image for the chunked digest, with its own body and slot size.
    let big = json_object(outputs, "mcuboot-ed25519-200k.bin");
    assert_eq!(json_field(big, "body_len"), "204800");
    assert_eq!(json_field(big, "slot_size"), "262144");
    assert_eq!(
        json_field(big, "body_drbg_label"),
        "image-fixture-body-200k"
    );
    assert_eq!(json_field(big, "expect_parse"), "Ok");
    // Only the fixture files (and the manifest) are in the directory.
    let mut on_disk: Vec<String> = Vec::new();
    for sub in ["", "keys", "rejected", "sigs"] {
        for entry in fs::read_dir(dir.join(sub)).expect("read fixture dir") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                let file = path.file_name().unwrap().to_string_lossy().into_owned();
                on_disk.push(if sub.is_empty() {
                    file
                } else {
                    format!("{sub}/{file}")
                });
            }
        }
    }
    on_disk.sort();
    let mut expected: Vec<String> = IMAGE_FIXTURES.iter().map(|s| (*s).to_owned()).collect();
    expected.push("MANIFEST.json".to_owned());
    expected.sort();
    assert_eq!(on_disk, expected);

    // The Ed25519 key is marked as a test key (and so are the others, above); KEYHASH is
    // SHA-256 of its SPKI.
    let pem = read("tests/fixtures/images/keys/ed25519-test-key.pem");
    assert!(
        pem.starts_with("# TEST KEY"),
        "the committed key says TEST KEY"
    );
    let spki = json_object(keys, "keys/ed25519-test-key.spki.der");
    assert_eq!(json_field(spki, "keyhash_hex"), json_field(spki, "sha256"));

    // Tools: pinned imgtool, recorded cryptography; hsslms pinned as in gen_lms_vectors.
    let tools = json_object(&manifest, "tools");
    assert_eq!(json_field(tools, "imgtool"), "2.4.0");
    assert_eq!(json_field(tools, "imgtool_requirement"), "imgtool==2.4.0");
    assert!(!json_field(tools, "cryptography").is_empty());
    let hsslms = json_object(&manifest, "hsslms");
    assert_eq!(json_field(hsslms, "package"), "hsslms==0.1.3");
    let sha = json_field(hsslms, "sha256");
    assert!(read("scripts/gen_lms_vectors.py").contains(sha));
    assert!(
        manifest.contains("\"generator\": \"scripts/gen_image_fixtures.py\""),
        "MANIFEST.json names its generator"
    );
    let script = read("scripts/gen_image_fixtures.py");
    assert!(script.contains("IMGTOOL_VERSION = \"2.4.0\""));
    // imgtool is an external tool prerequisite: the script never installs anything.
    assert!(!script.contains("ensurepip") && !script.contains("\"pip\""));

    // The TLV IDs the images were made with are tlv.rs's.
    let src = tlv_rs();
    let ids = json_object(&manifest, "tlv_ids");
    for (name, value) in tlv_ids(&src) {
        assert_eq!(
            json_field(ids, name),
            format!("{value:#06x}"),
            "{name}: regenerate the images after changing tlv.rs"
        );
    }
}

#[test]
#[ignore = "needs imgtool==2.4.0 on PATH (tool prerequisite), python3 and network access to files.pythonhosted.org"]
fn fixture_generator_round_trips() {
    let (ok, stdout, stderr) = run_capture(python_script("gen_image_fixtures.py").arg("--check"));
    assert!(
        ok,
        "gen_image_fixtures.py --check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("decode and re-encode byte-identically"));
    assert!(stdout.contains("fixtures match a fresh regeneration"));
}
