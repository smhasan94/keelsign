//! Known-answer tests for the key file formats: the RFC 9881 and RFC 8410 example keys,
//! and the committed image-fixture test keys (tests/fixtures/images/MANIFEST.json).

use keelsign::keys::{KeyAlgorithm, KeyIdentity, PrivateKey, hex};
use std::path::PathBuf;

/// RFC 9881 Appendix C.1.1.1: ML-DSA-44 private key, seed format, seed 00 01 .. 1f.
const RFC9881_MLDSA44_SEED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----
";

/// RFC 9881 Appendix C.1.2.1: ML-DSA-65 private key, seed format, seed 00 01 .. 1f.
const RFC9881_MLDSA65_SEED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----
";

/// SHA-256 of the RFC 9881 Appendix C.2 example public keys (DER SPKI) for the seed
/// above: ML-DSA-44, then ML-DSA-65.
const RFC9881_SPKI_SHA256: [&str; 2] = [
    "837832708c5236d951581f1fddf2b79991b3424a0486d16da1ddad0fd69701be",
    "b8b62131bfbe84433efb2273d7f5b87f7a22854a2cfd366fc2aead86d837c52d",
];

/// keelsign key IDs (first 16 bytes of SHA-256 of the FIPS 204 public key) of the
/// RFC 9881 example keys: ML-DSA-44, then ML-DSA-65.
const RFC9881_KEY_IDS: [&str; 2] = [
    "9f107644c1084526af3bc8098680b054",
    "d666806e11cee19a7c989f7445f90dd4",
];

/// RFC 8410 §10.3: Ed25519 private key without the public key (PKCS#8 v1).
const RFC8410_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
";

/// RFC 8410 §10.1: the matching Ed25519 public key.
const RFC8410_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
";

/// The KEYHASH (SHA-256 of the DER SPKI) of the RFC 8410 example key.
const RFC8410_KEYHASH: &str = "a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f";

/// DER prefix of a PKCS#8 v1 ML-DSA seed-form private key up to the OID's last byte
/// (`0x11` ML-DSA-44, `0x12` ML-DSA-65), then `04 22 80 20` and the 32-byte seed
/// (RFC 9881 §6).
const MLDSA_SEED_PKCS8_PREFIX: [u8; 18] = [
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x03, 0x00,
];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/images")
}

fn manifest() -> String {
    std::fs::read_to_string(fixtures().join("MANIFEST.json")).expect("read MANIFEST.json")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A PKCS#8 v1 ML-DSA seed-form private key for `seed`.
fn mldsa_seed_pkcs8(algorithm: KeyAlgorithm, seed: &[u8; 32]) -> Vec<u8> {
    let mut der = MLDSA_SEED_PKCS8_PREFIX.to_vec();
    der[17] = match algorithm {
        KeyAlgorithm::MlDsa44 => 0x11,
        KeyAlgorithm::MlDsa65 => 0x12,
        KeyAlgorithm::Ed25519 | KeyAlgorithm::LmsHss => unreachable!(),
    };
    der.extend_from_slice(&[0x04, 0x22, 0x80, 0x20]);
    der.extend_from_slice(seed);
    der
}

#[test]
fn rfc9881_seed_examples_load_and_reencode() {
    let cases = [
        (
            RFC9881_MLDSA44_SEED_PEM,
            KeyAlgorithm::MlDsa44,
            "30820532300b06096086480165030403110382052100",
            1334,
        ),
        (
            RFC9881_MLDSA65_SEED_PEM,
            KeyAlgorithm::MlDsa65,
            "308207b2300b0609608648016503040312038207a100",
            1974,
        ),
    ];
    for (i, (pem, algorithm, spki_header, spki_len)) in cases.into_iter().enumerate() {
        let key = PrivateKey::from_bytes(pem.as_bytes(), None).expect("load RFC 9881 key");
        assert_eq!(key.algorithm(), algorithm);
        // Re-encoding gives the RFC's bytes back exactly (PEM and DER).
        assert_eq!(key.to_pem().expect("pem").as_str(), pem, "{algorithm}");
        assert_eq!(key.to_pkcs8_der().expect("der").as_bytes().len(), 54);

        let spki = key.public_key_spki_der().expect("spki");
        let spki = spki.as_bytes();
        assert_eq!(spki.len(), spki_len, "{algorithm} SPKI length");
        assert_eq!(hex(&spki[..spki_header.len() / 2]), spki_header);
        // key_id_of is the first 16 bytes of SHA-256: matches the RFC C.2 public key's
        // SHA-256.
        assert_eq!(
            hex(&keelsign_verify::key_id_of(spki)),
            RFC9881_SPKI_SHA256[i][..32],
            "{algorithm}: SPKI is not the RFC 9881 C.2 public key"
        );
        assert_eq!(&spki[spki_header.len() / 2..], key.raw_public_key());
        assert_eq!(
            key.identity().to_string(),
            format!("key id: {}", RFC9881_KEY_IDS[i])
        );
    }
}

#[test]
fn rfc8410_ed25519_example_loads() {
    let key = PrivateKey::from_bytes(RFC8410_PRIVATE_PEM.as_bytes(), None).expect("load");
    assert_eq!(key.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(key.to_pem().expect("pem").as_str(), RFC8410_PRIVATE_PEM);
    assert_eq!(key.public_key_spki_pem().expect("spki"), RFC8410_PUBLIC_PEM);
    assert_eq!(
        key.identity(),
        KeyIdentity::KeyHash(unhex(RFC8410_KEYHASH).try_into().expect("32 bytes"))
    );
    let spki = key.public_key_spki_der().expect("spki");
    assert_eq!(
        &spki.as_bytes()[..12],
        keelsign_verify::ed25519::ED25519_SPKI_PREFIX
    );
}

#[test]
fn ed25519_fixture_key_keyhash_matches_manifest() {
    let bytes = std::fs::read(fixtures().join("keys/ed25519-test-key.pem")).expect("read key");
    let key = PrivateKey::from_bytes(&bytes, None).expect("load imgtool test key");
    assert_eq!(key.algorithm(), KeyAlgorithm::Ed25519);
    let spki = std::fs::read(fixtures().join("keys/ed25519-test-key.spki.der")).expect("spki");
    assert_eq!(key.public_key_spki_der().expect("spki").as_bytes(), spki);

    let KeyIdentity::KeyHash(keyhash) = key.identity() else {
        panic!("Ed25519 keys are identified by KEYHASH");
    };
    let keyhash = hex(&keyhash);
    assert_eq!(
        keyhash,
        "15bd85175f163ec727380037b5c48ae9f83fc2cb8e12fa5a678be4809f2b3190"
    );
    assert!(
        manifest().contains(&format!("\"keyhash_hex\": \"{keyhash}\"")),
        "MANIFEST.json records the KEYHASH {keyhash}"
    );
}

#[test]
fn mldsa_fixture_seed_key_ids_match_manifest() {
    let manifest = manifest();
    for (algorithm, seed, key_id) in [
        (
            KeyAlgorithm::MlDsa44,
            "2dbcae7f73a70dabad74c0f99e973083eff4c4d98ae225b6cfdbf7dd9c5b21da",
            "9a24dd433a22a6b1ff7209041aac49ba",
        ),
        (
            KeyAlgorithm::MlDsa65,
            "fe8c5dc4450640efcc8fc8875b410b3469f91b920fd930ef2d399e4098414502",
            "a602e37b4d644240d11cf33cbaccc553",
        ),
    ] {
        for needle in [
            format!("\"seed_hex\": \"{seed}\""),
            format!("\"key_id_hex\": \"{key_id}\""),
        ] {
            assert!(manifest.contains(&needle), "MANIFEST.json lacks {needle}");
        }
        let seed: [u8; 32] = unhex(seed).try_into().expect("32-byte seed");
        let der = mldsa_seed_pkcs8(algorithm, &seed);
        let key = PrivateKey::from_bytes(&der, None).expect("load seed-form DER");
        assert_eq!(key.algorithm(), algorithm);
        assert_eq!(key.to_pkcs8_der().expect("der").as_bytes(), der);
        assert_eq!(key.identity().to_string(), format!("key id: {key_id}"));
    }
}
