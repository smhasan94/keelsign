//! `keelsign inspect`: describe an MCUboot image, as text or as JSON (see
//! `docs/signing.md`, "inspect", and the schema `docs/inspect-schema.json`).
//!
//! The output depends only on the image bytes: it never contains the file's path, the
//! time or the terminal size, so it can be compared with committed snapshots.

use crate::keys::hex;
use keelsign_verify::image::{
    IMAGE_F_COMPRESSED_ARM_THUMB_FLT, IMAGE_F_COMPRESSED_LZMA1, IMAGE_F_COMPRESSED_LZMA2,
    IMAGE_F_ENCRYPTED_AES128, IMAGE_F_ENCRYPTED_AES256, IMAGE_F_NON_BOOTABLE, IMAGE_F_PIC,
    IMAGE_F_RAM_LOAD, IMAGE_F_ROM_FIXED, IMAGE_TLV_KEYHASH, IMAGE_TLV_SHA256, Image, ImageVersion,
    TlvArea, TlvKind,
};
use keelsign_verify::tlv::{KEY_ID_LEN, TLV_KEELSIGN_KEY_ID};
use serde_json::{Value, json};
use std::fmt::Write as _;

/// The `schema_version` of the JSON output. Within one version fields are never
/// removed, renamed or retyped; new fields are optional (docs/signing.md).
pub const SCHEMA_VERSION: u64 = 1;

/// The `format` of the JSON output.
pub const FORMAT: &str = "keelsign-inspect";

/// Values longer than this are shortened in the text output.
const SHORT_VALUE_LEN: usize = 16;

/// The MCUboot image flags, by name.
const FLAG_NAMES: [(u32, &str); 9] = [
    (IMAGE_F_PIC, "PIC"),
    (IMAGE_F_ENCRYPTED_AES128, "ENCRYPTED_AES128"),
    (IMAGE_F_ENCRYPTED_AES256, "ENCRYPTED_AES256"),
    (IMAGE_F_NON_BOOTABLE, "NON_BOOTABLE"),
    (IMAGE_F_RAM_LOAD, "RAM_LOAD"),
    (IMAGE_F_ROM_FIXED, "ROM_FIXED"),
    (IMAGE_F_COMPRESSED_LZMA1, "COMPRESSED_LZMA1"),
    (IMAGE_F_COMPRESSED_LZMA2, "COMPRESSED_LZMA2"),
    (IMAGE_F_COMPRESSED_ARM_THUMB_FLT, "COMPRESSED_ARM_THUMB_FLT"),
];

/// An LM-OTS parameter set: IANA name, n and p (RFC 8554 Table 1, SP 800-208 Table 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmotsType {
    /// IANA name.
    pub name: &'static str,
    /// Hash length in bytes.
    pub n: usize,
    /// Number of n-byte elements in the signature.
    pub p: usize,
}

/// An LMS parameter set: IANA name, m and h (RFC 8554 Table 2, SP 800-208 Table 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmsType {
    /// IANA name.
    pub name: &'static str,
    /// Node length in bytes.
    pub m: usize,
    /// Tree height.
    pub h: usize,
}

/// The SHA-256 and SHA-256/192 LM-OTS typecodes keelsign-verify knows.
pub fn lmots_type(typecode: u32) -> Option<LmotsType> {
    let (name, n, p) = match typecode {
        0x01 => ("LMOTS_SHA256_N32_W1", 32, 265),
        0x02 => ("LMOTS_SHA256_N32_W2", 32, 133),
        0x03 => ("LMOTS_SHA256_N32_W4", 32, 67),
        0x04 => ("LMOTS_SHA256_N32_W8", 32, 34),
        0x05 => ("LMOTS_SHA256_N24_W1", 24, 200),
        0x06 => ("LMOTS_SHA256_N24_W2", 24, 101),
        0x07 => ("LMOTS_SHA256_N24_W4", 24, 51),
        0x08 => ("LMOTS_SHA256_N24_W8", 24, 26),
        _ => return None,
    };
    Some(LmotsType { name, n, p })
}

/// The SHA-256 and SHA-256/192 LMS typecodes keelsign-verify knows.
pub fn lms_type(typecode: u32) -> Option<LmsType> {
    let (name, m, h) = match typecode {
        0x05 => ("LMS_SHA256_M32_H5", 32, 5),
        0x06 => ("LMS_SHA256_M32_H10", 32, 10),
        0x07 => ("LMS_SHA256_M32_H15", 32, 15),
        0x08 => ("LMS_SHA256_M32_H20", 32, 20),
        0x09 => ("LMS_SHA256_M32_H25", 32, 25),
        0x0A => ("LMS_SHA256_M24_H5", 24, 5),
        0x0B => ("LMS_SHA256_M24_H10", 24, 10),
        0x0C => ("LMS_SHA256_M24_H15", 24, 15),
        0x0D => ("LMS_SHA256_M24_H20", 24, 20),
        0x0E => ("LMS_SHA256_M24_H25", 24, 25),
        _ => return None,
    };
    Some(LmsType { name, m, h })
}

/// The structure of an HSS signature (RFC 8554 §6.2), read without verifying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HssSummary {
    /// Number of levels `L` (`Nspk + 1`).
    pub levels: u32,
    /// The LMS type of each level's signature, top level first.
    pub lms_types: Vec<&'static str>,
    /// The LM-OTS type of each level's signature, top level first.
    pub lmots_types: Vec<&'static str>,
    /// The leaf index `q` of the bottom-level signature (the one over the image).
    pub q: u32,
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
    }
}

/// Read the levels, typecodes and `q` of an HSS signature. `None` if it does not have
/// the exact length its typecodes dictate, uses an unknown typecode, or claims more than
/// eight levels.
pub fn hss_summary(signature: &[u8]) -> Option<HssSummary> {
    let mut cur = Cursor(signature);
    let nspk = cur.u32()?;
    if nspk > 7 {
        return None;
    }
    let mut summary = HssSummary {
        levels: nspk + 1,
        lms_types: Vec::new(),
        lmots_types: Vec::new(),
        q: 0,
    };
    for level in 0..=nspk {
        summary.q = cur.u32()?;
        let ots = lmots_type(cur.u32()?)?;
        cur.take(ots.n.checked_mul(ots.p.checked_add(1)?)?)?;
        let lms = lms_type(cur.u32()?)?;
        cur.take(lms.m.checked_mul(lms.h)?)?;
        summary.lmots_types.push(ots.name);
        summary.lms_types.push(lms.name);
        if level < nspk {
            // The next level's public key: lms_type, lmots_type, I, T[1].
            let next_lms = lms_type(cur.u32()?)?;
            lmots_type(cur.u32()?)?;
            cur.take(16 + next_lms.m)?;
        }
    }
    cur.0.is_empty().then_some(summary)
}

/// The MCUboot / keelsign name of a TLV type, if it has one.
pub fn tlv_name(tlv_type: u16) -> Option<&'static str> {
    Some(match TlvKind::of(tlv_type) {
        TlvKind::KeyHash => "KEYHASH",
        TlvKind::PubKey => "PUBKEY",
        TlvKind::Sha256 => "SHA256",
        TlvKind::Sha384 => "SHA384",
        TlvKind::Sha512 => "SHA512",
        TlvKind::Rsa2048Pss => "RSA2048_PSS",
        TlvKind::EcdsaSig => "ECDSA_SIG",
        TlvKind::Rsa3072Pss => "RSA3072_PSS",
        TlvKind::Ed25519 => "ED25519",
        TlvKind::SigPure => "SIG_PURE",
        TlvKind::Dependency => "DEPENDENCY",
        TlvKind::SecCnt => "SEC_CNT",
        TlvKind::BootRecord => "BOOT_RECORD",
        TlvKind::KeelsignKeyId => "KEELSIGN_KEY_ID",
        TlvKind::MlDsa44Sig => "KEELSIGN_MLDSA44_SIG",
        TlvKind::MlDsa65Sig => "KEELSIGN_MLDSA65_SIG",
        TlvKind::LmsHssSig => "KEELSIGN_LMS_HSS_SIG",
        TlvKind::KeelsignReserved(_) => "KEELSIGN_RESERVED",
        _ => return None,
    })
}

/// The signature kind (JSON `signatures[].kind`) of a TLV type, if it is a signature.
fn signature_kind(kind: TlvKind) -> Option<&'static str> {
    Some(match kind {
        TlvKind::Ed25519 => "ed25519",
        TlvKind::Rsa2048Pss => "rsa2048-pss",
        TlvKind::Rsa3072Pss => "rsa3072-pss",
        TlvKind::EcdsaSig => "ecdsa-p256",
        TlvKind::MlDsa44Sig => "ml-dsa-44",
        TlvKind::MlDsa65Sig => "ml-dsa-65",
        TlvKind::LmsHssSig => "lms-hss",
        _ => return None,
    })
}

fn version_string(v: &ImageVersion) -> String {
    format!("{}.{}.{}+{}", v.major, v.minor, v.revision, v.build_num)
}

fn hss_json(summary: &HssSummary) -> Value {
    json!({
        "levels": summary.levels,
        "lms_types": summary.lms_types,
        "lmots_types": summary.lmots_types,
        "q": summary.q,
    })
}

/// What a TLV's value means, where keelsign knows (JSON `decoded`), or null.
fn decode_tlv(kind: TlvKind, value: &[u8], digest: &[u8; 32]) -> Value {
    match kind {
        TlvKind::Sha256 => json!({"hash": "SHA-256", "matches_digest": value == digest}),
        TlvKind::Sha384 => json!({"hash": "SHA-384"}),
        TlvKind::Sha512 => json!({"hash": "SHA-512"}),
        TlvKind::KeyHash if value.len() == 32 => json!({"keyhash": hex(value)}),
        TlvKind::PubKey => {
            use pkcs8::der::Decode as _;
            match pkcs8::SubjectPublicKeyInfoRef::from_der(value) {
                Ok(spki) => json!({"algorithm_oid": spki.algorithm.oid.to_string()}),
                Err(_) => Value::Null,
            }
        }
        TlvKind::SecCnt => match <[u8; 4]>::try_from(value) {
            Ok(b) => json!({"security_counter": u32::from_le_bytes(b)}),
            Err(_) => Value::Null,
        },
        TlvKind::Dependency if value.len() == 12 => {
            // struct image_dependency: image_id, pad, pad16, image_version.
            let le16 = |i: usize| u16::from_le_bytes([value[i], value[i + 1]]);
            let le32 =
                |i: usize| u32::from_le_bytes([value[i], value[i + 1], value[i + 2], value[i + 3]]);
            let version = ImageVersion {
                major: value[4],
                minor: value[5],
                revision: le16(6),
                build_num: le32(8),
            };
            json!({"image_index": value[0], "version": version_string(&version)})
        }
        TlvKind::BootRecord => json!({"encoding": "CBOR"}),
        TlvKind::Ed25519 => json!({"algorithm": "Ed25519"}),
        TlvKind::Rsa2048Pss => json!({"algorithm": "RSA-2048-PSS"}),
        TlvKind::Rsa3072Pss => json!({"algorithm": "RSA-3072-PSS"}),
        TlvKind::EcdsaSig => json!({"algorithm": "ECDSA"}),
        TlvKind::KeelsignKeyId if value.len() == KEY_ID_LEN => json!({"key_id": hex(value)}),
        TlvKind::MlDsa44Sig => json!({"parameter_set": "ML-DSA-44"}),
        TlvKind::MlDsa65Sig => json!({"parameter_set": "ML-DSA-65"}),
        TlvKind::LmsHssSig => match hss_summary(value) {
            Some(s) => {
                let mut v = hss_json(&s);
                v["parameter_set"] = json!("LMS/HSS");
                v
            }
            None => json!({"parameter_set": "LMS/HSS"}),
        },
        _ => Value::Null,
    }
}

fn area_json(area: &TlvArea<'_>, digest: &[u8; 32]) -> Value {
    let bytes = area.bytes();
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let tlv_tot = u16::from_le_bytes([bytes[2], bytes[3]]);
    let tlvs: Vec<Value> = area
        .iter()
        .map(|tlv| {
            json!({
                "type": tlv.tlv_type,
                "type_hex": format!("{:#06x}", tlv.tlv_type),
                "name": tlv_name(tlv.tlv_type),
                "len": tlv.value.len(),
                "value_hex": hex(tlv.value),
                "decoded": decode_tlv(tlv.kind(), tlv.value, digest),
            })
        })
        .collect();
    json!({"magic": magic, "tlv_tot": tlv_tot, "tlvs": tlvs})
}

/// The JSON report of the image `bytes` (already parsed as `image`) with digest `digest`.
pub fn to_json(bytes: &[u8], image: &Image<'_>, digest: &[u8; 32]) -> Value {
    let header = image.header();
    let raw = image.raw_header();
    let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let flags = header.flags.0;
    let names: Vec<&str> = FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();

    let sha256: Vec<&[u8]> = image
        .tlvs()
        .filter(|t| t.tlv_type == IMAGE_TLV_SHA256)
        .map(|t| t.value)
        .collect();
    let sha256_tlv_matches = match sha256.as_slice() {
        [only] => json!(*only == digest),
        _ => Value::Null,
    };

    let key_ids: Vec<String> = image
        .tlvs()
        .filter(|t| t.tlv_type == TLV_KEELSIGN_KEY_ID && t.value.len() == KEY_ID_LEN)
        .map(|t| hex(t.value))
        .collect();
    let keyhashes: Vec<String> = image
        .tlvs()
        .filter(|t| t.tlv_type == IMAGE_TLV_KEYHASH && t.value.len() == 32)
        .map(|t| hex(t.value))
        .collect();
    // The image's key ID for its PQ signatures: the single unprotected key-ID TLV, when it
    // is KEY_ID_LEN bytes (otherwise null, as for `key_ids`).
    let unprotected_key_ids: Vec<&[u8]> = image
        .unprotected()
        .iter()
        .filter(|t| t.tlv_type == TLV_KEELSIGN_KEY_ID)
        .map(|t| t.value)
        .collect();
    let pq_key_id = match unprotected_key_ids.as_slice() {
        [only] if only.len() == KEY_ID_LEN => json!(hex(only)),
        _ => Value::Null,
    };

    let mut signatures = Vec::new();
    for area in image.protected().into_iter().chain([image.unprotected()]) {
        let mut previous: Option<(u16, &[u8])> = None;
        for tlv in area.iter() {
            let kind = tlv.kind();
            if let Some(name) = signature_kind(kind) {
                let pq = matches!(
                    kind,
                    TlvKind::MlDsa44Sig | TlvKind::MlDsa65Sig | TlvKind::LmsHssSig
                );
                // Paired only with a 32-byte KEYHASH immediately before it, as
                // keelsign-verify's select_ed25519_signature requires.
                let keyhash = match previous {
                    Some((IMAGE_TLV_KEYHASH, v)) if !pq && v.len() == 32 => json!(hex(v)),
                    _ => Value::Null,
                };
                let lms = match kind {
                    TlvKind::LmsHssSig => hss_summary(tlv.value)
                        .map(|s| hss_json(&s))
                        .unwrap_or(Value::Null),
                    _ => Value::Null,
                };
                signatures.push(json!({
                    "kind": name,
                    "area": if area.is_protected() { "protected" } else { "unprotected" },
                    "len": tlv.value.len(),
                    "keyhash": keyhash,
                    "key_id": if pq { pq_key_id.clone() } else { Value::Null },
                    "paired": if pq { Value::Null } else { json!(!keyhash.is_null()) },
                    "lms": lms,
                }));
            }
            previous = Some((tlv.tlv_type, tlv.value));
        }
    }

    json!({
        "schema_version": SCHEMA_VERSION,
        "format": FORMAT,
        "file_len": bytes.len(),
        "tlv_end": image.tlv_end(),
        "trailing_bytes": crate::image_file::trailing_bytes(bytes, image),
        "header": {
            "magic": magic,
            "load_addr": header.load_addr,
            "hdr_size": header.hdr_size,
            "protect_tlv_size": header.protect_tlv_size,
            "img_size": header.img_size,
            "flags": {
                "raw": flags,
                "names": names,
                "unknown_bits": header.flags.unknown_bits(),
            },
            "version": {
                "major": header.version.major,
                "minor": header.version.minor,
                "revision": header.version.revision,
                "build_num": header.version.build_num,
                "string": version_string(&header.version),
            },
        },
        "digest": {"sha256": hex(digest), "sha256_tlv_matches": sha256_tlv_matches},
        "protected": image.protected().map(|a| area_json(a, digest)),
        "unprotected": area_json(image.unprotected(), digest),
        "key_ids": key_ids,
        "keyhashes": keyhashes,
        "signatures": signatures,
    })
}

/// A hex value for the text output: in full up to 16 bytes, otherwise the first 16
/// bytes, `…` and the length.
fn short_hex(hex_value: &str) -> String {
    let len = hex_value.len() / 2;
    if len <= SHORT_VALUE_LEN {
        hex_value.to_owned()
    } else {
        format!(
            "{}… ({len} bytes)",
            hex_value.get(..2 * SHORT_VALUE_LEN).unwrap_or(hex_value)
        )
    }
}

/// A JSON scalar for the text output (`null` as `none`, booleans as yes / no).
fn scalar(v: &Value) -> String {
    match v {
        Value::Null => "none".into(),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::String(s) => s.clone(),
        Value::Array(items) if items.is_empty() => "none".into(),
        Value::Array(items) => items.iter().map(scalar).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn u64_of(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

fn write_area(out: &mut String, title: &str, area: &Value) {
    if area.is_null() {
        let _ = writeln!(out, "{title}: none");
        return;
    }
    let _ = writeln!(
        out,
        "{title}: magic {:#06x}, tlv_tot {}",
        u64_of(&area["magic"]),
        u64_of(&area["tlv_tot"])
    );
    for tlv in area["tlvs"].as_array().into_iter().flatten() {
        let name = tlv["name"].as_str().unwrap_or("unknown");
        let _ = writeln!(
            out,
            "  tlv {} {name}, {} bytes: {}",
            tlv["type_hex"].as_str().unwrap_or(""),
            u64_of(&tlv["len"]),
            short_hex(tlv["value_hex"].as_str().unwrap_or(""))
        );
        if let Some(decoded) = tlv["decoded"].as_object() {
            for (key, value) in decoded {
                let _ = writeln!(out, "    {}: {}", key.replace('_', " "), scalar(value));
            }
        }
    }
}

/// The text report: one `key: value` per line, TLVs in indented blocks. Mirrors
/// [`to_json`] (`report` is its output).
pub fn to_human(report: &Value) -> String {
    let mut out = String::new();
    let h = &report["header"];
    let flags = &h["flags"];
    let flag_names = scalar(&flags["names"]);
    let lines = [
        ("format", scalar(&report["format"])),
        ("schema version", scalar(&report["schema_version"])),
        ("file length", scalar(&report["file_len"])),
        ("tlv end", scalar(&report["tlv_end"])),
        ("trailing bytes", scalar(&report["trailing_bytes"])),
    ];
    for (k, v) in lines {
        let _ = writeln!(out, "{k}: {v}");
    }
    let _ = writeln!(out, "header:");
    let _ = writeln!(out, "  magic: {:#010x}", u64_of(&h["magic"]));
    let _ = writeln!(out, "  load address: {:#010x}", u64_of(&h["load_addr"]));
    let _ = writeln!(out, "  header size: {}", u64_of(&h["hdr_size"]));
    let _ = writeln!(
        out,
        "  protected TLV size: {}",
        u64_of(&h["protect_tlv_size"])
    );
    let _ = writeln!(out, "  image size: {}", u64_of(&h["img_size"]));
    let _ = writeln!(
        out,
        "  flags: {:#010x} ({flag_names}; unknown bits {:#010x})",
        u64_of(&flags["raw"]),
        u64_of(&flags["unknown_bits"])
    );
    let _ = writeln!(out, "  version: {}", scalar(&h["version"]["string"]));
    let _ = writeln!(out, "digest:");
    let _ = writeln!(out, "  sha256: {}", scalar(&report["digest"]["sha256"]));
    let _ = writeln!(
        out,
        "  sha256 tlv matches: {}",
        scalar(&report["digest"]["sha256_tlv_matches"])
    );
    write_area(&mut out, "protected tlv area", &report["protected"]);
    write_area(&mut out, "unprotected tlv area", &report["unprotected"]);
    let _ = writeln!(out, "key ids: {}", scalar(&report["key_ids"]));
    let _ = writeln!(out, "keyhashes: {}", scalar(&report["keyhashes"]));
    let signatures = report["signatures"].as_array().cloned().unwrap_or_default();
    if signatures.is_empty() {
        let _ = writeln!(out, "signatures: none");
    } else {
        let _ = writeln!(out, "signatures:");
    }
    for sig in &signatures {
        let _ = writeln!(
            out,
            "  {} ({}, {} bytes):",
            scalar(&sig["kind"]),
            scalar(&sig["area"]),
            u64_of(&sig["len"])
        );
        if sig["paired"].is_boolean() {
            let _ = writeln!(out, "    keyhash: {}", scalar(&sig["keyhash"]));
            let _ = writeln!(out, "    paired: {}", scalar(&sig["paired"]));
        } else {
            let _ = writeln!(out, "    key id: {}", scalar(&sig["key_id"]));
        }
        if let Some(lms) = sig["lms"].as_object() {
            for (key, value) in lms {
                let _ = writeln!(out, "    {}: {}", key.replace('_', " "), scalar(value));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keelsign_verify::lms::ParameterPolicy;

    #[test]
    fn lms_typecode_table_matches_keelsign_verify_policy() {
        let all = ParameterPolicy::rfc_8554_all_sets();
        let mut allowed = 0;
        for lms in 0..=0x20u32 {
            for ots in 0..=0x20u32 {
                let ours = match (lms_type(lms), lmots_type(ots)) {
                    (Some(l), Some(o)) => l.m == o.n,
                    _ => false,
                };
                assert_eq!(all.allows(lms, ots), ours, "lms {lms:#x} lmots {ots:#x}");
                allowed += usize::from(ours);
            }
        }
        // 5 heights x 4 widths x 2 hashes.
        assert_eq!(allowed, 40);
        // Names carry the parameters they are tabulated with.
        for code in 0..=0x20u32 {
            if let Some(l) = lms_type(code) {
                assert!(l.name.contains(&format!("_M{}_H{}", l.m, l.h)), "{l:?}");
            }
            if let Some(o) = lmots_type(code) {
                assert!(o.name.contains(&format!("_N{}_", o.n)), "{o:?}");
            }
        }
    }

    #[test]
    fn hss_summary_rejects_bad_lengths() {
        assert_eq!(hss_summary(&[]), None);
        assert_eq!(hss_summary(&[0, 0, 0, 8]), None);
        // L = 1, q = 3, LMOTS_SHA256_N32_W8 (C + 34 * 32), LMS_SHA256_M32_H5 (5 * 32).
        let mut sig = vec![0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4];
        sig.extend(vec![0u8; 32 * 35]);
        sig.extend([0, 0, 0, 5]);
        sig.extend(vec![0u8; 32 * 5]);
        let summary = hss_summary(&sig).expect("parses");
        assert_eq!(summary.levels, 1);
        assert_eq!(summary.q, 3);
        assert_eq!(summary.lms_types, ["LMS_SHA256_M32_H5"]);
        assert_eq!(summary.lmots_types, ["LMOTS_SHA256_N32_W8"]);
        sig.push(0);
        assert_eq!(hss_summary(&sig), None);
        sig.truncate(sig.len() - 2);
        assert_eq!(hss_summary(&sig), None);
    }

    #[test]
    fn short_hex_shortens_long_values() {
        assert_eq!(short_hex("00ff"), "00ff");
        assert_eq!(short_hex(&"ab".repeat(16)), "ab".repeat(16));
        assert_eq!(
            short_hex(&"ab".repeat(17)),
            format!("{}… (17 bytes)", "ab".repeat(16))
        );
    }
}
