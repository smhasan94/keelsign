//! The exact DER structure of the files `keelsign keygen` and `keelsign pubkey` write:
//! standard OIDs (NIST CSOR / RFC 9881 §2, RFC 8410 §3) with absent parameters, the
//! RFC 9881 seed form, the RFC 8410 v1 Ed25519 layout, SPKI headers and the PBES2 /
//! scrypt / AES-256-CBC parameters of encrypted keys.

use keelsign::keys::{ID_ED25519, ID_ML_DSA_44, ID_ML_DSA_65, hex};
use pkcs8::der::Decode as _;
use pkcs8::spki::{AssociatedAlgorithmIdentifier as _, ObjectIdentifier};
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use std::path::{Path, PathBuf};
use std::process::Command;

const PASSPHRASE: &str = "correct horse battery staple";

/// One DER TLV: (tag, contents, rest of the input).
fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = der[0];
    let (len, header) = match der[1] {
        n if n < 0x80 => (usize::from(n), 2),
        0x81 => (usize::from(der[2]), 3),
        0x82 => (usize::from(der[2]) << 8 | usize::from(der[3]), 4),
        other => panic!("unexpected DER length byte {other:#04x}"),
    };
    (tag, &der[header..header + len], &der[header + len..])
}

/// The TLVs inside a constructed value, as (tag, contents).
fn children(mut contents: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while !contents.is_empty() {
        let (tag, value, rest) = tlv(contents);
        out.push((tag, value));
        contents = rest;
    }
    out
}

/// The dotted OID of an OBJECT IDENTIFIER's contents.
fn oid(contents: &[u8]) -> String {
    ObjectIdentifier::from_bytes(contents)
        .expect("valid OID")
        .to_string()
}

fn integer(contents: &[u8]) -> u64 {
    contents
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("formats")
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn keelsign(args: &[&std::ffi::OsStr]) {
    let out = Command::new(env!("CARGO_BIN_EXE_keelsign"))
        .args(args)
        .output()
        .expect("run keelsign");
    assert!(
        out.status.success(),
        "keelsign {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Check a private key `AlgorithmIdentifier`: exactly one OID, no parameters.
fn assert_algorithm_identifier(contents: &[u8], expected: &ObjectIdentifier) {
    let fields = children(contents);
    assert_eq!(fields.len(), 1, "parameters must be absent");
    assert_eq!(fields[0].0, 0x06, "OBJECT IDENTIFIER");
    assert_eq!(fields[0].1, expected.as_bytes());
    assert_eq!(oid(fields[0].1), expected.to_string());
}

#[test]
fn generated_files_carry_the_standard_oids() {
    // The OID constants are the NIST CSOR / RFC 9881 / RFC 8410 values, and agree with
    // the ml-dsa and ed25519 crates.
    assert_eq!(ID_ML_DSA_44.to_string(), "2.16.840.1.101.3.4.3.17");
    assert_eq!(ID_ML_DSA_65.to_string(), "2.16.840.1.101.3.4.3.18");
    assert_eq!(ID_ED25519.to_string(), "1.3.101.112");
    assert_eq!(ml_dsa::MlDsa44::ALGORITHM_IDENTIFIER.oid, ID_ML_DSA_44);
    assert_eq!(ml_dsa::MlDsa65::ALGORITHM_IDENTIFIER.oid, ID_ML_DSA_65);
    assert_eq!(ed25519_dalek::pkcs8::ALGORITHM_ID.oid, ID_ED25519);

    let dir = scratch("oids");
    let pw_file = dir.join("pw.txt");
    std::fs::write(&pw_file, format!("{PASSPHRASE}\n")).expect("write");

    // (algorithm, OID, SPKI header hex, SPKI length)
    let cases = [
        (
            "ml-dsa-44",
            ID_ML_DSA_44,
            "30820532300b06096086480165030403110382052100",
            1334,
        ),
        (
            "ml-dsa-65",
            ID_ML_DSA_65,
            "308207b2300b0609608648016503040312038207a100",
            1974,
        ),
        ("ed25519", ID_ED25519, "302a300506032b6570032100", 44),
    ];
    for (alg, expected_oid, spki_header, spki_len) in cases {
        let key = dir.join(format!("{alg}.der"));
        let pem = dir.join(format!("{alg}.pem"));
        let spki = dir.join(format!("{alg}.spki.der"));
        let enc = dir.join(format!("{alg}.enc.der"));
        keelsign(&[
            "keygen".as_ref(),
            "--alg".as_ref(),
            alg.as_ref(),
            "--out".as_ref(),
            key.as_os_str(),
            "--format".as_ref(),
            "der".as_ref(),
        ]);
        keelsign(&[
            "keygen".as_ref(),
            "--alg".as_ref(),
            alg.as_ref(),
            "--out".as_ref(),
            pem.as_os_str(),
        ]);
        keelsign(&[
            "pubkey".as_ref(),
            "--key".as_ref(),
            key.as_os_str(),
            "--out".as_ref(),
            spki.as_os_str(),
            "--format".as_ref(),
            "der".as_ref(),
        ]);
        keelsign(&[
            "keygen".as_ref(),
            "--alg".as_ref(),
            alg.as_ref(),
            "--out".as_ref(),
            enc.as_os_str(),
            "--format".as_ref(),
            "der".as_ref(),
            "--passphrase-file".as_ref(),
            pw_file.as_os_str(),
        ]);

        // PrivateKeyInfo v1: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING }.
        let der = std::fs::read(&key).expect("read key");
        let (tag, contents, rest) = tlv(&der);
        assert_eq!((tag, rest.len()), (0x30, 0), "{alg}: one SEQUENCE");
        let fields = children(contents);
        assert_eq!(fields.len(), 3, "{alg}: v1 has no attributes or publicKey");
        assert_eq!(fields[0], (0x02, &[0u8][..]), "{alg}: version v1 (0)");
        assert_eq!(fields[1].0, 0x30);
        assert_algorithm_identifier(fields[1].1, &expected_oid);
        assert_eq!(fields[2].0, 0x04, "{alg}: privateKey OCTET STRING");
        let private_key = fields[2].1;
        if alg == "ed25519" {
            // RFC 8410 §7: CurvePrivateKey ::= OCTET STRING (32 bytes), version v1.
            assert_eq!(der.len(), 48);
            assert_eq!(hex(&der[..16]), "302e020100300506032b657004220420");
            assert_eq!(private_key.len(), 34);
        } else {
            // RFC 9881 §6: seed [0] IMPLICIT OCTET STRING (SIZE (32)).
            assert_eq!(der.len(), 54, "{alg}: seed-form file");
            assert_eq!(private_key.len(), 34);
            assert_eq!(&private_key[..2], [0x80, 0x20], "{alg}: [0] seed, 32 bytes");
        }

        // The PEM file is the same structure under the label PRIVATE KEY.
        let pem_text = std::fs::read_to_string(&pem).expect("read pem");
        let (label, doc) = pkcs8::der::Document::from_pem(&pem_text).expect("PEM");
        assert_eq!(label, "PRIVATE KEY");
        assert_eq!(doc.as_bytes().len(), der.len());
        // Everything but the 32 random key bytes is the same.
        let header = der.len() - 32;
        assert_eq!(
            doc.as_bytes()[..header],
            der[..header],
            "{alg}: same header"
        );

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }.
        let spki_der = std::fs::read(&spki).expect("read spki");
        assert_eq!(spki_der.len(), spki_len, "{alg}: SPKI length");
        assert_eq!(hex(&spki_der[..spki_header.len() / 2]), spki_header);
        let (_, contents, _) = tlv(&spki_der);
        let fields = children(contents);
        assert_eq!(fields.len(), 2);
        assert_algorithm_identifier(fields[0].1, &expected_oid);
        assert_eq!(fields[1].0, 0x03, "BIT STRING");
        assert_eq!(fields[1].1[0], 0, "no unused bits");

        // EncryptedPrivateKeyInfo: PBES2 { scrypt, AES-256-CBC } around the same
        // PrivateKeyInfo.
        let enc_der = std::fs::read(&enc).expect("read encrypted key");
        let (_, contents, rest) = tlv(&enc_der);
        assert!(rest.is_empty());
        let fields = children(contents);
        assert_eq!(fields.len(), 2);
        let alg_id = children(fields[0].1);
        assert_eq!(oid(alg_id[0].1), "1.2.840.113549.1.5.13", "PBES2");
        let pbes2 = children(alg_id[1].1);
        let kdf = children(pbes2[0].1);
        assert_eq!(oid(kdf[0].1), "1.3.6.1.4.1.11591.4.11", "scrypt");
        let scrypt = children(kdf[1].1);
        assert_eq!(scrypt[0].0, 0x04, "salt OCTET STRING");
        assert_eq!(scrypt[0].1.len(), 16, "16-byte salt");
        assert_eq!(integer(scrypt[1].1), 16384, "cost parameter N");
        assert_eq!(integer(scrypt[2].1), 8, "block size r");
        assert_eq!(integer(scrypt[3].1), 1, "parallelization p");
        let cipher = children(pbes2[1].1);
        assert_eq!(oid(cipher[0].1), "2.16.840.1.101.3.4.1.42", "AES-256-CBC");
        assert_eq!(cipher[1].1.len(), 16, "16-byte IV");
        assert_eq!(fields[1].0, 0x04, "encryptedData OCTET STRING");

        let decrypted = EncryptedPrivateKeyInfoRef::from_der(&enc_der)
            .expect("parse")
            .decrypt(PASSPHRASE)
            .expect("decrypt");
        let inner = PrivateKeyInfoRef::from_der(decrypted.as_bytes()).expect("inner");
        assert_eq!(inner.algorithm.oid, expected_oid, "{alg}: inner OID");
        assert!(inner.algorithm.parameters.is_none());
        assert!(inner.public_key.is_none(), "{alg}: inner key is v1");
    }
}
