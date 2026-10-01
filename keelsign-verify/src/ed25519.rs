//! The Ed25519 half of a hybrid image (SHA-46): MCUboot's `IMAGE_TLV_KEYHASH` +
//! `IMAGE_TLV_ED25519` pair, its selection rules and the signature check.
//!
//! An imgtool Ed25519 image carries, in the unprotected TLV area, a 32-byte KEYHASH TLV
//! (`0x01`, SHA-256 of the signer's DER SubjectPublicKeyInfo, RFC 8410) immediately
//! followed by a 64-byte ED25519 TLV (`0x24`): an Ed25519 signature (RFC 8032, pure
//! Ed25519) over the 32-byte image digest `M`, the value of the `SHA256` TLV
//! (MCUboot `image_validate.c` at `a8ffd2c`: `:87-90` the 64-byte signature, `:364-403`
//! and `:433` the KEYHASH lookup and pairing). keelsign's hybrid images keep exactly that
//! pair ([docs/image-format.md, Hybrid layout][spec]).
//!
//! Trusted Ed25519 keys live in the same [`TrustedKeys`](crate::TrustedKeys) set as the
//! post-quantum keys, keyed by their KEYHASH ([`keyhash_of`]); see
//! [`TrustedKeys::with_ed25519`](crate::TrustedKeys::with_ed25519).
//!
//! The signature check needs the `ed25519` feature (`ed25519-dalek`, `verify_strict`).
//! Without it [`verify_signature`] is [`Ed25519Error::NotEnabled`] and [`is_enabled`] is
//! `false`; the selection rules and [`keyhash_of`] are always compiled.
//!
//! [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#hybrid-layout

use core::fmt;

use sha2::{Digest, Sha256};

use crate::image::{IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH};

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410 §4): `SEQUENCE {
/// SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }` around the 32 raw key
/// bytes. imgtool hashes `prefix || public key` into the KEYHASH TLV.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of the KEYHASH TLV value: a full SHA-256.
pub const KEYHASH_LEN: usize = 32;

/// Length of the ED25519 TLV value: an Ed25519 signature (RFC 8032 §5.1.6).
pub const SIGNATURE_LEN: usize = 64;

/// MCUboot's KEYHASH of an Ed25519 key: SHA-256 of its DER SubjectPublicKeyInfo.
pub type KeyHash = [u8; KEYHASH_LEN];

/// The KEYHASH of a raw 32-byte Ed25519 public key: SHA-256 of
/// [`ED25519_SPKI_PREFIX`] `||` `public_key`, the value imgtool writes to the KEYHASH TLV
/// (`--public-key-format hash`). Always compiled, with or without the `ed25519` feature.
pub fn keyhash_of(public_key: &[u8; 32]) -> KeyHash {
    let mut hasher = Sha256::new();
    hasher.update(ED25519_SPKI_PREFIX);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// One trusted Ed25519 public key (the raw 32 bytes, RFC 8032 §5.1.5), borrowed from
/// wherever the device stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Key<'a> {
    /// The raw encoded public key: the last 32 bytes of its SubjectPublicKeyInfo.
    pub public_key: &'a [u8; 32],
}

impl Ed25519Key<'_> {
    /// The key's KEYHASH ([`keyhash_of`]).
    pub fn keyhash(&self) -> KeyHash {
        keyhash_of(self.public_key)
    }
}

/// Why the Ed25519 half of an image was rejected. Wrapped in
/// [`Error::Ed25519`](crate::Error::Ed25519), so the error names the classical half.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519Error {
    /// The policy needs the Ed25519 half but this build lacks the `ed25519` feature.
    NotEnabled,
    /// The unprotected TLV area has no ED25519 TLV.
    Missing,
    /// The unprotected TLV area has more than one ED25519 TLV or more than one KEYHASH
    /// TLV. Fails closed rather than picking one (MCUboot tries each pair in turn).
    Multiple,
    /// The TLV immediately before the ED25519 TLV is not a KEYHASH TLV.
    Unpaired,
    /// The KEYHASH TLV is not [`KEYHASH_LEN`] (32) bytes.
    InvalidKeyHash,
    /// The ED25519 TLV is not [`SIGNATURE_LEN`] (64) bytes.
    InvalidSignatureLength,
    /// No trusted Ed25519 key has the image's KEYHASH.
    KeyNotTrusted,
    /// The trusted Ed25519 key is not a valid point encoding.
    InvalidPublicKey,
    /// The Ed25519 signature does not verify (`verify_strict`) over the image digest.
    SignatureInvalid,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Ed25519Error::NotEnabled => "Ed25519 is not enabled in this build",
            Ed25519Error::Missing => "no ED25519 signature TLV",
            Ed25519Error::Multiple => "more than one ED25519 or KEYHASH TLV",
            Ed25519Error::Unpaired => "the ED25519 TLV does not follow a KEYHASH TLV",
            Ed25519Error::InvalidKeyHash => "KEYHASH TLV has the wrong length",
            Ed25519Error::InvalidSignatureLength => "ED25519 TLV has the wrong length",
            Ed25519Error::KeyNotTrusted => "KEYHASH is not in the trusted Ed25519 key set",
            Ed25519Error::InvalidPublicKey => "trusted Ed25519 public key is malformed",
            Ed25519Error::SignatureInvalid => "Ed25519 signature is invalid",
        })
    }
}

impl core::error::Error for Ed25519Error {}

/// The KEYHASH and ED25519 TLVs picked out of a TLV area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedEd25519<'t> {
    /// Value of the KEYHASH TLV, length-checked ([`KEYHASH_LEN`]).
    pub keyhash: &'t [u8],
    /// Value of the ED25519 TLV, length-checked ([`SIGNATURE_LEN`]).
    pub signature: &'t [u8],
}

/// Pick the single KEYHASH + ED25519 pair out of `tlvs`, given as `(type, value)` pairs
/// of the unprotected TLV area. Other TLV types are ignored.
///
/// After scanning every TLV it requires, in order:
/// 1. an ED25519 TLV ([`Ed25519Error::Missing`]);
/// 2. exactly one ED25519 TLV and at most one KEYHASH TLV ([`Ed25519Error::Multiple`]);
/// 3. the TLV immediately before the ED25519 TLV to be the KEYHASH TLV
///    ([`Ed25519Error::Unpaired`]);
/// 4. a 32-byte KEYHASH ([`Ed25519Error::InvalidKeyHash`]);
/// 5. a 64-byte signature ([`Ed25519Error::InvalidSignatureLength`]).
pub fn select_ed25519_signature<'t, I>(tlvs: I) -> Result<SelectedEd25519<'t>, Ed25519Error>
where
    I: IntoIterator<Item = (u16, &'t [u8])>,
{
    type Tlv<'t> = Option<(u16, &'t [u8])>;
    let (mut keyhashes, mut signatures) = (0usize, 0usize);
    // The TLV just before the (first) ED25519 TLV, and the ED25519 value.
    let mut pair: Option<(Tlv<'t>, &'t [u8])> = None;
    let mut previous: Tlv<'t> = None;
    for (tlv_type, value) in tlvs {
        if tlv_type == IMAGE_TLV_KEYHASH {
            keyhashes = keyhashes.saturating_add(1);
        } else if tlv_type == IMAGE_TLV_ED25519 {
            signatures = signatures.saturating_add(1);
            if pair.is_none() {
                pair = Some((previous, value));
            }
        }
        previous = Some((tlv_type, value));
    }
    let (before, signature) = pair.ok_or(Ed25519Error::Missing)?;
    if signatures > 1 || keyhashes > 1 {
        return Err(Ed25519Error::Multiple);
    }
    let keyhash = match before {
        Some((IMAGE_TLV_KEYHASH, keyhash)) => keyhash,
        _ => return Err(Ed25519Error::Unpaired),
    };
    if keyhash.len() != KEYHASH_LEN {
        return Err(Ed25519Error::InvalidKeyHash);
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(Ed25519Error::InvalidSignatureLength);
    }
    Ok(SelectedEd25519 { keyhash, signature })
}

/// Whether this build verifies Ed25519 signatures: the `ed25519` feature.
pub const fn is_enabled() -> bool {
    cfg!(feature = "ed25519")
}

/// Verify the Ed25519 `signature` over `message` (the 32-byte image digest `M`) under
/// `public_key`, with `ed25519-dalek`'s `verify_strict` (RFC 8032 §5.1.7 plus rejection
/// of small-order keys and `R`, and of non-canonical `R` and `s` (`s ≥ ℓ`); it only ever
/// rejects more than MCUboot's verifier). A non-canonical encoding of the key itself is
/// not rejected: `VerifyingKey::from_bytes` reduces `y` mod `p`.
///
/// Errors, in order: [`Ed25519Error::NotEnabled`] without the `ed25519` feature;
/// [`Ed25519Error::InvalidSignatureLength`] unless `signature` is 64 bytes;
/// [`Ed25519Error::InvalidPublicKey`] if `public_key` does not decode to a curve point;
/// [`Ed25519Error::SignatureInvalid`] if the signature does not verify.
#[cfg(feature = "ed25519")]
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let signature: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| Ed25519Error::InvalidSignatureLength)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Ed25519Error::InvalidPublicKey)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Ed25519Error::SignatureInvalid)
}

/// Verify the Ed25519 `signature` over `message` under `public_key`: without the
/// `ed25519` feature this is always [`Ed25519Error::NotEnabled`].
#[cfg(not(feature = "ed25519"))]
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    let _ = (public_key, message, signature);
    Err(Ed25519Error::NotEnabled)
}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::collections::BTreeSet;
    use std::string::ToString;
    use std::vec::Vec;

    use super::*;
    use crate::image::{IMAGE_TLV_SHA256, Image};

    const SPKI: &[u8] =
        include_bytes!("../../tests/fixtures/images/keys/ed25519-test-key.spki.der");
    const GOLDEN: &[u8] = include_bytes!("../../tests/fixtures/images/mcuboot-ed25519.bin");
    const HYBRID: &[u8] =
        include_bytes!("../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin");

    fn test_key() -> [u8; 32] {
        SPKI[12..].try_into().unwrap()
    }

    #[test]
    fn keyhash_is_sha256_of_spki_der() {
        assert_eq!(SPKI.len(), 44);
        assert_eq!(SPKI[..12], ED25519_SPKI_PREFIX);
        let pk = test_key();
        let full: [u8; 32] = Sha256::digest(SPKI).into();
        assert_eq!(keyhash_of(&pk), full);
        assert_eq!(Ed25519Key { public_key: &pk }.keyhash(), full);
        // It is the KEYHASH TLV imgtool wrote into both Ed25519 fixtures.
        for image in [GOLDEN, HYBRID] {
            let image = Image::parse(image).unwrap();
            let selected = select_ed25519_signature(image.unprotected().pairs()).unwrap();
            assert_eq!(selected.keyhash, full);
        }
        // A different key has a different KEYHASH.
        let mut other = pk;
        other[0] ^= 1;
        assert_ne!(keyhash_of(&other), full);
    }

    /// The SHA256 TLV (`M`) and the selected pair of a fixture.
    fn parts(data: &[u8]) -> ([u8; 32], [u8; 64]) {
        let image = Image::parse(data).unwrap();
        let m = image
            .unprotected()
            .pairs()
            .find(|(t, _)| *t == IMAGE_TLV_SHA256)
            .unwrap()
            .1;
        let selected = select_ed25519_signature(image.unprotected().pairs()).unwrap();
        (
            m.try_into().unwrap(),
            selected.signature.try_into().unwrap(),
        )
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn golden_signature_verifies_and_bit_flips_fail() {
        assert!(is_enabled());
        let pk = test_key();
        for data in [GOLDEN, HYBRID] {
            let (m, sig) = parts(data);
            assert_eq!(verify_signature(&pk, &m, &sig), Ok(()));
            // Every bit of the signature, and of M.
            for byte in 0..64 {
                for bit in 0..8 {
                    let mut bad = sig;
                    bad[byte] ^= 1 << bit;
                    assert_eq!(
                        verify_signature(&pk, &m, &bad),
                        Err(Ed25519Error::SignatureInvalid),
                        "sig byte {byte} bit {bit}"
                    );
                }
            }
            for byte in 0..32 {
                let mut other = m;
                other[byte] ^= 0x01;
                assert_eq!(
                    verify_signature(&pk, &other, &sig),
                    Err(Ed25519Error::SignatureInvalid),
                    "M byte {byte}"
                );
            }
            // Wrong lengths.
            assert_eq!(
                verify_signature(&pk, &m, &sig[..63]),
                Err(Ed25519Error::InvalidSignatureLength)
            );
            let mut long = sig.to_vec();
            long.push(0);
            assert_eq!(
                verify_signature(&pk, &m, &long),
                Err(Ed25519Error::InvalidSignatureLength)
            );
            // Another key: the signature does not verify.
            let mut other_key = pk;
            other_key[0] ^= 0x01;
            assert!(verify_signature(&other_key, &m, &sig).is_err());
        }
        // A public key that is not a curve point: y = 2 is not on edwards25519.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        let (m, sig) = parts(GOLDEN);
        assert_eq!(
            verify_signature(&not_a_point, &m, &sig),
            Err(Ed25519Error::InvalidPublicKey)
        );
    }

    #[cfg(not(feature = "ed25519"))]
    #[test]
    fn verify_signature_is_not_enabled_without_the_feature() {
        assert!(!is_enabled());
        let (m, sig) = parts(GOLDEN);
        assert_eq!(
            verify_signature(&test_key(), &m, &sig),
            Err(Ed25519Error::NotEnabled)
        );
    }

    fn select(tlvs: &[(u16, Vec<u8>)]) -> Result<SelectedEd25519<'_>, Ed25519Error> {
        select_ed25519_signature(tlvs.iter().map(|(t, v)| (*t, v.as_slice())))
    }

    #[test]
    fn select_pair_rules() {
        let kh = |n: usize| (IMAGE_TLV_KEYHASH, std::vec![0x11; n]);
        let sig = |n: usize| (IMAGE_TLV_ED25519, std::vec![0x22; n]);
        let sha = (IMAGE_TLV_SHA256, std::vec![0x33; 32]);
        let key_id = (0x4BA0, std::vec![0x44; 16]);
        let lms = (0x4BA3, std::vec![0x55; 1292]);

        // The imgtool layout, with keelsign TLVs after it.
        let ok = [sha.clone(), kh(32), sig(64), key_id.clone(), lms.clone()];
        let selected = select(&ok).unwrap();
        assert_eq!(selected.keyhash, [0x11; 32]);
        assert_eq!(selected.signature, [0x22; 64]);
        // Position in the area does not matter, adjacency does.
        assert!(select(&[key_id.clone(), kh(32), sig(64)]).is_ok());

        type Case = (&'static str, Vec<(u16, Vec<u8>)>, Ed25519Error);
        let cases: [Case; 11] = [
            ("empty", Vec::new(), Ed25519Error::Missing),
            (
                "no ED25519",
                Vec::from([sha.clone(), kh(32)]),
                Ed25519Error::Missing,
            ),
            (
                "no ED25519, two KEYHASH",
                Vec::from([kh(32), kh(32)]),
                Ed25519Error::Missing,
            ),
            (
                "two pairs",
                Vec::from([kh(32), sig(64), kh(32), sig(64)]),
                Ed25519Error::Multiple,
            ),
            (
                "two ED25519 after one KEYHASH",
                Vec::from([kh(32), sig(64), sig(64)]),
                Ed25519Error::Multiple,
            ),
            (
                "two KEYHASH, one ED25519",
                Vec::from([kh(32), kh(32), sig(64)]),
                Ed25519Error::Multiple,
            ),
            (
                "ED25519 alone",
                Vec::from([sha.clone(), sig(64)]),
                Ed25519Error::Unpaired,
            ),
            (
                "ED25519 first",
                Vec::from([sig(64), kh(32)]),
                Ed25519Error::Unpaired,
            ),
            (
                "a TLV between KEYHASH and ED25519",
                Vec::from([kh(32), sha.clone(), sig(64)]),
                Ed25519Error::Unpaired,
            ),
            (
                "31-byte KEYHASH",
                Vec::from([kh(31), sig(64)]),
                Ed25519Error::InvalidKeyHash,
            ),
            (
                "63-byte signature",
                Vec::from([kh(32), sig(63)]),
                Ed25519Error::InvalidSignatureLength,
            ),
        ];
        for (name, tlvs, expected) in &cases {
            assert_eq!(select(tlvs), Err(*expected), "{name}");
        }
        // More length cases, and the order of the length checks: KEYHASH first.
        for n in [0, 1, 33, 64] {
            assert_eq!(select(&[kh(n), sig(64)]), Err(Ed25519Error::InvalidKeyHash));
            assert_eq!(select(&[kh(n), sig(0)]), Err(Ed25519Error::InvalidKeyHash));
        }
        for n in [0, 32, 65, 128] {
            assert_eq!(
                select(&[kh(32), sig(n)]),
                Err(Ed25519Error::InvalidSignatureLength)
            );
        }
        // Multiple before Unpaired, Missing before Multiple.
        assert_eq!(select(&[sig(64), sig(64)]), Err(Ed25519Error::Multiple));
        assert_eq!(select(&[kh(1), kh(1)]), Err(Ed25519Error::Missing));
    }

    #[test]
    fn ed25519_errors_display_distinctly() {
        let all = [
            Ed25519Error::NotEnabled,
            Ed25519Error::Missing,
            Ed25519Error::Multiple,
            Ed25519Error::Unpaired,
            Ed25519Error::InvalidKeyHash,
            Ed25519Error::InvalidSignatureLength,
            Ed25519Error::KeyNotTrusted,
            Ed25519Error::InvalidPublicKey,
            Ed25519Error::SignatureInvalid,
        ];
        let messages: BTreeSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(messages.len(), all.len());
        assert!(messages.iter().all(|m| !m.is_empty()));
    }
}
