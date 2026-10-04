//! `keelsign inspect`, run as the real binary (SHA-51 AC3 and TP2): its JSON validates
//! against docs/inspect-schema.json, agrees with the fixture MANIFEST, and both outputs
//! match the committed snapshots (written by scripts/gen_inspect_snapshots.py).

mod common;

use common::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn schema() -> Value {
    let text = std::fs::read_to_string(repo().join("docs/inspect-schema.json"))
        .expect("read docs/inspect-schema.json");
    serde_json::from_str(&text).expect("the schema is JSON")
}

fn inspect_json(path: &Path) -> Value {
    let out = keelsign(&[&"inspect", &"--json", &path]);
    assert_exit(&out, 0);
    serde_json::from_slice(&out.stdout).expect("inspect --json writes JSON")
}

fn snapshots_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/inspect")
}

/// The images with committed snapshots, from the snapshot directory.
fn snapshot_images() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(snapshots_dir())
        .expect("read snapshots")
        .filter_map(|e| {
            let name = e.expect("entry").file_name().to_string_lossy().into_owned();
            name.strip_suffix(".json").map(str::to_owned)
        })
        .collect();
    names.sort();
    names
}

/// "0x0010 0x4ba0" -> [0x10, 0x4ba0]; "" -> [].
fn manifest_types(s: &str) -> Vec<u64> {
    s.split_whitespace()
        .map(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).expect("hex type"))
        .collect()
}

fn manifest_lens(s: &str) -> Vec<u64> {
    s.split_whitespace()
        .map(|t| t.parse().expect("length"))
        .collect()
}

fn area_types(area: &Value) -> (Vec<u64>, Vec<u64>) {
    let tlvs = area["tlvs"].as_array().cloned().unwrap_or_default();
    (
        tlvs.iter()
            .map(|t| t["type"].as_u64().expect("type"))
            .collect(),
        tlvs.iter()
            .map(|t| t["len"].as_u64().expect("len"))
            .collect(),
    )
}

/// Every object schema under `value` forbids additional properties.
fn assert_strict(value: &Value, at: &str) {
    match value {
        Value::Object(map) => {
            if map.get("type") == Some(&Value::String("object".into())) {
                assert_eq!(
                    map.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{at}: additionalProperties must be false"
                );
                assert!(map.contains_key("properties"), "{at}: lists its properties");
                assert!(
                    map.contains_key("required"),
                    "{at}: lists its required fields"
                );
            }
            for (key, child) in map {
                assert_strict(child, &format!("{at}/{key}"));
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                assert_strict(child, &format!("{at}/{i}"));
            }
        }
        _ => {}
    }
}

/// AC3: docs/inspect-schema.json is a valid Draft 2020-12 schema, strict
/// (`additionalProperties: false` throughout, every top-level field required) and pins
/// `schema_version` to 1.
#[test]
fn inspect_schema_is_a_valid_2020_12_schema_and_strict() {
    let schema = schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    jsonschema::draft202012::meta::validate(&schema).expect("valid against the 2020-12 metaschema");
    assert_strict(&schema, "#");

    let properties: Vec<&String> = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .collect();
    let mut required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    required.sort_unstable();
    let mut properties: Vec<&str> = properties.iter().map(|s| s.as_str()).collect();
    properties.sort_unstable();
    assert_eq!(required, properties, "every top-level field is required");
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        keelsign::inspect::SCHEMA_VERSION
    );
    assert_eq!(
        schema["properties"]["format"]["const"],
        keelsign::inspect::FORMAT
    );

    // The validator rejects reports that break the contract.
    let validator = jsonschema::draft202012::new(&schema).expect("compile");
    let good = inspect_json(&fixture_path("mcuboot-ed25519.bin"));
    assert!(validator.is_valid(&good));
    let mut extra = good.clone();
    extra["surprise"] = Value::Bool(true);
    assert!(!validator.is_valid(&extra), "unknown top-level field");
    let mut nested_extra = good.clone();
    nested_extra["header"]["surprise"] = Value::Bool(true);
    assert!(!validator.is_valid(&nested_extra), "unknown nested field");
    let mut missing = good.clone();
    missing.as_object_mut().expect("object").remove("digest");
    assert!(!validator.is_valid(&missing), "missing field");
    let mut version = good;
    version["schema_version"] = Value::from(2);
    assert!(!validator.is_valid(&version), "schema_version 2");
}

/// TP2: `inspect --json` of every parseable fixture validates against the schema and
/// agrees with MANIFEST.json (header, TLVs per area, digest, tlv_end, key IDs, keyhashes,
/// signature kinds).
#[test]
fn inspect_json_validates_against_schema_for_every_fixture() {
    let validator = jsonschema::draft202012::new(&schema()).expect("compile schema");
    let manifest = manifest();
    let outputs = manifest["outputs"].as_object().expect("outputs");
    let mut checked = 0;
    for (name, entry) in outputs {
        if entry["expect_parse"] != "Ok" {
            continue;
        }
        let path = fixture_path(name);
        let report = inspect_json(&path);
        if let Err(e) = validator.validate(&report) {
            panic!("{name}: {e}");
        }
        let bytes = fixture(name);
        assert_eq!(report["file_len"], bytes.len(), "{name}");
        assert_eq!(report["tlv_end"], entry["tlv_end"], "{name}");
        assert_eq!(
            report["trailing_bytes"].as_u64().expect("u64"),
            bytes.len() as u64 - entry["tlv_end"].as_u64().expect("tlv_end"),
            "{name}"
        );
        let header = &entry["header"];
        for field in ["hdr_size", "img_size", "protect_tlv_size"] {
            assert_eq!(report["header"][field], header[field], "{name} {field}");
        }
        assert_eq!(report["header"]["flags"]["raw"], header["flags"], "{name}");
        assert_eq!(
            report["header"]["version"]["string"], header["version"],
            "{name}"
        );
        assert_eq!(report["header"]["magic"], 0x96F3_B83Du32, "{name}");
        assert_eq!(report["digest"]["sha256"], entry["digest_hex"], "{name}");

        let (types, lens) = if report["protected"].is_null() {
            (vec![], vec![])
        } else {
            area_types(&report["protected"])
        };
        let s = |k: &str| entry[k].as_str().unwrap_or_default().to_owned();
        assert_eq!(types, manifest_types(&s("protected_tlvs")), "{name}");
        assert_eq!(lens, manifest_lens(&s("protected_tlv_lens")), "{name}");
        let (types, lens) = area_types(&report["unprotected"]);
        assert_eq!(types, manifest_types(&s("unprotected_tlvs")), "{name}");
        assert_eq!(lens, manifest_lens(&s("unprotected_tlv_lens")), "{name}");

        let key_ids: Vec<&str> = report["key_ids"]
            .as_array()
            .expect("key_ids")
            .iter()
            .map(|v| v.as_str().expect("hex"))
            .collect();
        // The MANIFEST names the signing key's ID, also where the fixture drops the
        // key-ID TLV or (bad-key-id) flips a bit of it.
        if let Some(key_id) = entry["key_id_hex"].as_str()
            && s("unprotected_tlvs").contains("0x4ba0")
            && !name.contains("bad-key-id")
        {
            assert!(key_ids.contains(&key_id), "{name}: {key_ids:?}");
        }
        let keyhashes: Vec<&str> = report["keyhashes"]
            .as_array()
            .expect("keyhashes")
            .iter()
            .map(|v| v.as_str().expect("hex"))
            .collect();
        if let Some(keyhash) = entry["keyhash_hex"].as_str() {
            assert_eq!(keyhashes, [keyhash], "{name}");
        }

        // Signature kinds follow the signature TLVs of the MANIFEST, in order.
        let kinds: Vec<&str> = report["signatures"]
            .as_array()
            .expect("signatures")
            .iter()
            .map(|v| v["kind"].as_str().expect("kind"))
            .collect();
        let expected: Vec<&str> = manifest_types(&s("protected_tlvs"))
            .into_iter()
            .chain(manifest_types(&s("unprotected_tlvs")))
            .filter_map(|t| match t {
                0x20 => Some("rsa2048-pss"),
                0x22 => Some("ecdsa-p256"),
                0x23 => Some("rsa3072-pss"),
                0x24 => Some("ed25519"),
                0x4BA1 => Some("ml-dsa-44"),
                0x4BA2 => Some("ml-dsa-65"),
                0x4BA3 => Some("lms-hss"),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, expected, "{name}");
        checked += 1;
    }
    assert!(checked >= 50, "checked {checked} fixtures");
}

fn assert_matches_snapshot(json: bool) {
    let images = snapshot_images();
    assert_eq!(images.len(), 7, "{images:?}");
    for image in &images {
        let path = fixture_path(&format!("{image}.bin"));
        let out = if json {
            keelsign(&[&"inspect", &"--json", &path])
        } else {
            keelsign(&[&"inspect", &path])
        };
        assert_exit(&out, 0);
        let ext = if json { "json" } else { "txt" };
        let snapshot =
            std::fs::read(snapshots_dir().join(format!("{image}.{ext}"))).expect("read snapshot");
        assert!(
            out.stdout == snapshot,
            "{image}.{ext} differs from `keelsign inspect`; regenerate with \
             python3 scripts/gen_inspect_snapshots.py\n--- got\n{}",
            stdout(&out)
        );
        let text = stdout(&out);
        assert!(
            !text.contains("tests/fixtures") && !text.contains(".bin"),
            "{image}: the output names no path"
        );
    }
}

/// TP2: the text output matches the committed snapshots.
#[test]
fn inspect_human_output_matches_snapshots() {
    assert_matches_snapshot(false);
}

/// TP2: the JSON output matches the committed snapshots.
#[test]
fn inspect_json_output_matches_snapshots() {
    assert_matches_snapshot(true);
}

fn tlv<'a>(report: &'a Value, area: &str, tlv_type: u64) -> &'a Value {
    report[area]["tlvs"]
        .as_array()
        .expect("tlvs")
        .iter()
        .find(|t| t["type"] == tlv_type)
        .unwrap_or_else(|| panic!("no TLV {tlv_type:#x} in {area}"))
}

/// TP2 and the SHA-240 follow-up: known TLVs are decoded (SEC_CNT, DEPENDENCY, key ID,
/// ML-DSA parameter set, HSS levels and typecodes), signatures are listed with their
/// pairing, and the digest is compared with the SHA256 TLV.
#[test]
fn inspect_decodes_known_tlvs() {
    let golden = inspect_json(&fixture_path("mcuboot-ed25519.bin"));
    assert_eq!(
        tlv(&golden, "protected", 0x50)["decoded"]["security_counter"],
        7
    );
    let dependency = &tlv(&golden, "protected", 0x40)["decoded"];
    assert_eq!(dependency["image_index"], 1);
    assert_eq!(dependency["version"], "1.2.3+4");
    assert_eq!(
        tlv(&golden, "protected", 0x60)["decoded"]["encoding"],
        "CBOR"
    );
    assert_eq!(
        tlv(&golden, "unprotected", 0x10)["decoded"]["matches_digest"],
        true
    );
    assert_eq!(golden["digest"]["sha256_tlv_matches"], true);
    let sig = &golden["signatures"][0];
    assert_eq!(sig["kind"], "ed25519");
    assert_eq!(sig["paired"], true);
    assert_eq!(
        sig["keyhash"],
        hex(&keelsign_verify::keyhash_of(&ed25519_test_public_key()))
    );
    assert_eq!(tlv(&golden, "unprotected", 0x24)["name"], "ED25519");

    let hss = inspect_json(&fixture_path("keelsign-hss2-m32-h5h5.bin"));
    let lms = &hss["signatures"][0]["lms"];
    assert_eq!(lms["levels"], 2);
    assert_eq!(
        lms["lms_types"],
        serde_json::json!(["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H5"])
    );
    assert_eq!(
        lms["lmots_types"],
        serde_json::json!(["LMOTS_SHA256_N32_W8", "LMOTS_SHA256_N32_W8"])
    );
    assert_eq!(
        hss["signatures"][0]["key_id"],
        manifest_entry("keelsign-hss2-m32-h5h5.bin")["key_id_hex"]
    );
    assert_eq!(tlv(&hss, "unprotected", 0x4BA3)["decoded"]["levels"], 2);
    let single = inspect_json(&fixture_path("keelsign-lms-m32-h5.bin"));
    assert_eq!(single["signatures"][0]["lms"]["levels"], 1);

    let mldsa = inspect_json(&fixture_path("keelsign-mldsa65-protected-tlvs.bin"));
    assert_eq!(
        tlv(&mldsa, "unprotected", 0x4BA2)["decoded"]["parameter_set"],
        "ML-DSA-65"
    );
    assert_eq!(
        tlv(&mldsa, "unprotected", 0x4BA0)["decoded"]["key_id"],
        manifest_entry("keelsign-mldsa65-protected-tlvs.bin")["key_id_hex"]
    );
    assert_eq!(mldsa["signatures"][0]["kind"], "ml-dsa-65");
    assert_eq!(mldsa["signatures"][0]["paired"], Value::Null);

    let dual = inspect_json(&fixture_path("keelsign-dual-pq-invalid.bin"));
    let kinds: Vec<&Value> = dual["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|s| &s["kind"])
        .collect();
    assert_eq!(kinds, ["lms-hss", "ml-dsa-44"]);

    let hybrid = inspect_json(&fixture_path("keelsign-hybrid-protected-tlvs.bin"));
    let kinds: Vec<&Value> = hybrid["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|s| &s["kind"])
        .collect();
    assert_eq!(kinds, ["ed25519", "lms-hss"]);
    assert_eq!(tlv(&hybrid, "protected", 0x10A0)["name"], Value::Null);
    assert_eq!(tlv(&hybrid, "protected", 0x10A0)["decoded"], Value::Null);

    let unpaired = inspect_json(&fixture_path("keelsign-hybrid-unpaired-ed25519.bin"));
    assert_eq!(unpaired["signatures"][0]["paired"], false);
    assert_eq!(unpaired["signatures"][0]["keyhash"], Value::Null);

    let bad = inspect_json(&fixture_path("keelsign-hybrid-bad-sha256.bin"));
    assert_eq!(bad["digest"]["sha256_tlv_matches"], false);
    for name in [
        "keelsign-hybrid-no-sha256.bin",
        "keelsign-hybrid-two-sha256.bin",
    ] {
        assert_eq!(
            inspect_json(&fixture_path(name))["digest"]["sha256_tlv_matches"],
            Value::Null,
            "{name}"
        );
    }
    let padded = inspect_json(&fixture_path("mcuboot-ed25519-padded.bin"));
    assert_eq!(padded["trailing_bytes"], 8192 - 2315);
    let encrypted = inspect_json(&fixture_path("keelsign-hybrid-flag-encrypted.bin"));
    assert!(
        encrypted["header"]["flags"]["names"]
            .as_array()
            .expect("names")
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.starts_with("ENCRYPTED_"))),
        "{}",
        encrypted["header"]["flags"]
    );

    // An image `keelsign sign` wrote.
    let dir = scratch("inspect", "decodes");
    let key = keygen(&dir, "ml-dsa-44", "pq", None);
    let signed = dir.join("signed.bin");
    assert_exit(
        &keelsign(&[
            &"sign",
            &"--key",
            &key,
            &fixture_path("mcuboot-ed25519.bin"),
            &signed,
        ]),
        0,
    );
    let report = inspect_json(&signed);
    let kinds: Vec<&Value> = report["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|s| &s["kind"])
        .collect();
    assert_eq!(kinds, ["ed25519", "ml-dsa-44"]);
    assert_eq!(
        report["signatures"][1]["key_id"],
        hex(&keelsign_verify::key_id_of(
            &load_key(&key).raw_public_key()
        ))
    );
    assert_eq!(report["digest"]["sha256_tlv_matches"], true);
}

/// TP2: a file that is not a little-endian MCUboot image is refused with exit 7.
#[test]
fn inspect_rejects_non_images_with_exit_7() {
    let dir = scratch("inspect", "non_images");
    let golden = fixture("mcuboot-ed25519.bin");
    let cases = [
        ("garbage.bin", vec![b'x'; 64], "bad header magic"),
        ("empty.bin", Vec::new(), "truncated"),
        (
            "truncated.bin",
            golden[..golden.len() - 1].to_vec(),
            "truncated",
        ),
        (
            "bigendian.bin",
            fixture("rejected/mcuboot-ed25519-bigendian.bin"),
            "bad header magic",
        ),
    ];
    for (name, bytes, reason) in cases {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write");
        for json in [false, true] {
            let out = if json {
                keelsign(&[&"inspect", &"--json", &path])
            } else {
                keelsign(&[&"inspect", &path])
            };
            assert_exit(&out, 7);
            assert!(out.stdout.is_empty(), "{name}: nothing on stdout");
            assert!(stderr(&out).contains(reason), "{name}: {}", stderr(&out));
            assert!(stderr(&out).contains(name), "{name}: names the file");
        }
    }
    // A missing file is an I/O error.
    assert_exit(&keelsign(&[&"inspect", &dir.join("missing.bin")]), 1);
}
