//! The trusted-key set and key-ID lookup.

use sha2::{Digest, Sha256};

use crate::algorithm::Algorithm;
use crate::error::{Error, KeySetError};
use crate::lms;
use crate::tlv::KEY_ID_LEN;

/// A key ID: the first [`KEY_ID_LEN`] bytes of the SHA-256 of the raw public key
/// (see [`key_id_of`]).
pub type KeyId = [u8; KEY_ID_LEN];

/// One trusted public key, borrowed from wherever the device stores it (typically flash).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedKey<'a> {
    /// The algorithm the key is for.
    pub algorithm: Algorithm,
    /// The raw encoded public key.
    pub public_key: &'a [u8],
}

/// The key ID of a raw encoded public key: SHA-256 of the bytes, truncated to
/// [`KEY_ID_LEN`] (16) bytes.
///
/// The bytes hashed are exactly the public key as held in the trusted set: the FIPS 204
/// encoding for ML-DSA, and the HSS public key `u32 L || LMS public key` (RFC 8554 §6.1)
/// for LMS/HSS. The signer puts this ID in the
/// [`TLV_KEELSIGN_KEY_ID`](crate::tlv::TLV_KEELSIGN_KEY_ID) TLV. Specified in
/// [docs/image-format.md, Key ID](https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#key-id). The Ed25519 half of a hybrid image
/// is identified separately, by MCUboot's `IMAGE_TLV_KEYHASH` (SHA-256 of the DER
/// SubjectPublicKeyInfo, all 32 bytes).
pub fn key_id_of(public_key: &[u8]) -> KeyId {
    let digest = Sha256::digest(public_key);
    let mut id = [0u8; KEY_ID_LEN];
    for (out, byte) in id.iter_mut().zip(digest.iter()) {
        *out = *byte;
    }
    id
}

/// A set of at most `N` trusted public keys, looked up by key ID.
///
/// No heap: the keys are borrowed and their IDs are computed once, in
/// [`TrustedKeys::new`]. Lookup compares IDs with plain byte comparison; key IDs are
/// public (they travel in the image), so this leaks nothing.
#[derive(Clone, Copy, Debug)]
pub struct TrustedKeys<'a, const N: usize> {
    entries: [Option<(KeyId, TrustedKey<'a>)>; N],
    len: usize,
}

impl<'a, const N: usize> TrustedKeys<'a, N> {
    /// Build a key set from `keys`, computing each key ID.
    ///
    /// Fails with [`KeySetError::Capacity`] if there are more than `N` keys,
    /// [`KeySetError::InvalidPublicKeyLength`] if a key is empty or its length is wrong
    /// for its algorithm, and [`KeySetError::DuplicateKeyId`] if two keys have the same
    /// ID.
    ///
    /// ML-DSA keys have one exact length each. An LMS/HSS key must be 52 or 60 bytes
    /// ([`lms::PUBLIC_KEY_LENS`](crate::lms::PUBLIC_KEY_LENS): SHA-256/192 or SHA-256)
    /// and pass [`lms::check_public_key`]: `L` in `1..=8` and a known LMS typecode whose m
    /// gives exactly its length (52 for m = 24, 60 for m = 32). The keelsign parameter
    /// policy is not applied here: a well-formed key outside it (an LM-OTS W2 key, say)
    /// is accepted and refused with [`Error::UnsupportedParameterSet`] when it verifies a
    /// signature.
    pub fn new(keys: &[TrustedKey<'a>]) -> Result<Self, KeySetError> {
        if keys.len() > N {
            return Err(KeySetError::Capacity);
        }
        let mut entries: [Option<(KeyId, TrustedKey<'a>)>; N] = [None; N];
        let mut len = 0;
        for key in keys {
            if key.public_key.is_empty() {
                return Err(KeySetError::InvalidPublicKeyLength(key.algorithm));
            }
            if let Some(expected) = key.algorithm.public_key_len()
                && key.public_key.len() != expected
            {
                return Err(KeySetError::InvalidPublicKeyLength(key.algorithm));
            }
            // The 52 / 60 rule first as a fast pre-check, then the key's own typecode.
            if key.algorithm == Algorithm::LmsHss
                && (!lms::PUBLIC_KEY_LENS.contains(&key.public_key.len())
                    || lms::check_public_key(key.public_key).is_err())
            {
                return Err(KeySetError::InvalidPublicKeyLength(key.algorithm));
            }
            let id = key_id_of(key.public_key);
            if entries
                .iter()
                .flatten()
                .any(|(existing, _)| *existing == id)
            {
                return Err(KeySetError::DuplicateKeyId);
            }
            let slot = entries.get_mut(len).ok_or(KeySetError::Capacity)?;
            *slot = Some((id, *key));
            len += 1;
        }
        Ok(Self { entries, len })
    }

    /// Number of keys in the set.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the set has no keys.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The trusted key with ID `key_id` (the raw key-ID TLV value).
    ///
    /// Fails with [`Error::InvalidKeyId`] if `key_id` is not [`KEY_ID_LEN`] bytes and
    /// [`Error::KeyNotTrusted`] if no key has that ID.
    pub fn find(&self, key_id: &[u8]) -> Result<&TrustedKey<'a>, Error> {
        let key_id: &KeyId = key_id.try_into().map_err(|_| Error::InvalidKeyId)?;
        self.entries
            .iter()
            .flatten()
            .find(|(id, _)| id == key_id)
            .map(|(_, key)| key)
            .ok_or(Error::KeyNotTrusted)
    }
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

    use super::*;

    static MLDSA44_PK: [u8; 1312] = [0x44; 1312];
    static MLDSA65_PK: [u8; 1952] = [0x65; 1952];
    static LMS_PK_A: [u8; 60] = lms::test_public_key(0xA0);
    static LMS_PK_B: [u8; 60] = lms::test_public_key(0xB0);

    fn key(algorithm: Algorithm, public_key: &[u8]) -> TrustedKey<'_> {
        TrustedKey {
            algorithm,
            public_key,
        }
    }

    #[test]
    fn lookup_by_id_selects_each_of_two_keys() {
        let a = key(Algorithm::MlDsa44, &MLDSA44_PK);
        let b = key(Algorithm::MlDsa65, &MLDSA65_PK);
        let keys = TrustedKeys::<4>::new(&[a, b]).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(!keys.is_empty());
        assert_eq!(keys.find(&key_id_of(&MLDSA44_PK)), Ok(&a));
        assert_eq!(keys.find(&key_id_of(&MLDSA65_PK)), Ok(&b));

        // Same algorithm, two keys.
        let a = key(Algorithm::LmsHss, &LMS_PK_A);
        let b = key(Algorithm::LmsHss, &LMS_PK_B);
        let keys = TrustedKeys::<2>::new(&[a, b]).unwrap();
        assert_eq!(keys.find(&key_id_of(&LMS_PK_A)), Ok(&a));
        assert_eq!(keys.find(&key_id_of(&LMS_PK_B)), Ok(&b));
    }

    #[test]
    fn unknown_key_id_is_key_not_trusted() {
        let keys = TrustedKeys::<2>::new(&[key(Algorithm::LmsHss, &LMS_PK_A)]).unwrap();
        assert_eq!(keys.find(&key_id_of(&LMS_PK_B)), Err(Error::KeyNotTrusted));
        assert_eq!(keys.find(&[0u8; KEY_ID_LEN]), Err(Error::KeyNotTrusted));

        let empty = TrustedKeys::<2>::new(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.find(&key_id_of(&LMS_PK_A)), Err(Error::KeyNotTrusted));
    }

    #[test]
    fn capacity_overflow_is_key_set_error_capacity() {
        let a = key(Algorithm::LmsHss, &LMS_PK_A);
        let b = key(Algorithm::LmsHss, &LMS_PK_B);
        assert_eq!(
            TrustedKeys::<1>::new(&[a, b]).unwrap_err(),
            KeySetError::Capacity
        );
        assert_eq!(
            TrustedKeys::<0>::new(&[a]).unwrap_err(),
            KeySetError::Capacity
        );
        // Exactly at capacity is fine.
        assert_eq!(TrustedKeys::<2>::new(&[a, b]).unwrap().len(), 2);
    }

    #[test]
    fn duplicate_key_id_is_rejected_at_construction() {
        let a = key(Algorithm::LmsHss, &LMS_PK_A);
        assert_eq!(
            TrustedKeys::<4>::new(&[a, a]).unwrap_err(),
            KeySetError::DuplicateKeyId
        );
        // Same bytes from a different buffer are the same key ID.
        let copy = LMS_PK_A;
        let a2 = key(Algorithm::LmsHss, &copy);
        let b = key(Algorithm::LmsHss, &LMS_PK_B);
        assert_eq!(
            TrustedKeys::<4>::new(&[a, b, a2]).unwrap_err(),
            KeySetError::DuplicateKeyId
        );
    }

    #[test]
    fn wrong_length_ml_dsa_public_key_is_rejected() {
        for (alg, pk) in [
            (Algorithm::MlDsa44, &MLDSA44_PK[..]),
            (Algorithm::MlDsa65, &MLDSA65_PK[..]),
        ] {
            let short = &pk[..pk.len() - 1];
            assert_eq!(
                TrustedKeys::<2>::new(&[key(alg, short)]).unwrap_err(),
                KeySetError::InvalidPublicKeyLength(alg)
            );
            assert_eq!(
                TrustedKeys::<2>::new(&[key(alg, &[])]).unwrap_err(),
                KeySetError::InvalidPublicKeyLength(alg)
            );
        }
        // An ML-DSA-65-sized key labelled ML-DSA-44 is also rejected.
        assert_eq!(
            TrustedKeys::<2>::new(&[key(Algorithm::MlDsa44, &MLDSA65_PK)]).unwrap_err(),
            KeySetError::InvalidPublicKeyLength(Algorithm::MlDsa44)
        );
    }

    #[test]
    fn empty_public_key_is_rejected_for_every_algorithm() {
        for &alg in Algorithm::ALL {
            assert_eq!(
                TrustedKeys::<2>::new(&[key(alg, &[])]).unwrap_err(),
                KeySetError::InvalidPublicKeyLength(alg),
                "{alg:?}"
            );
            // Also when it follows a valid key.
            assert_eq!(
                TrustedKeys::<2>::new(&[key(Algorithm::LmsHss, &LMS_PK_A), key(alg, &[])])
                    .unwrap_err(),
                KeySetError::InvalidPublicKeyLength(alg),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn key_id_is_truncated_sha256_of_public_key() {
        // FIPS 180-4 example: SHA-256("abc") =
        // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad.
        let full: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(key_id_of(b"abc"), full[..KEY_ID_LEN]);

        // The set finds a key by the truncated SHA-256 of its bytes.
        let keys = TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &LMS_PK_A)]).unwrap();
        let digest: [u8; 32] = Sha256::digest(LMS_PK_A).into();
        assert!(keys.find(&digest[..KEY_ID_LEN]).is_ok());
    }

    /// An HSS public key header: `L`, LMS typecode, LM-OTS typecode.
    fn lms_header(levels: u32, lms_type: u32, ots_type: u32) -> [u8; 12] {
        let mut header = [0u8; 12];
        header[..4].copy_from_slice(&levels.to_be_bytes());
        header[4..8].copy_from_slice(&lms_type.to_be_bytes());
        header[8..].copy_from_slice(&ots_type.to_be_bytes());
        header
    }

    #[test]
    fn lms_public_key_must_be_52_or_60_bytes() {
        for (lms_type, ots_type, valid_len) in [(0x0Au32, 0x08u32, 52usize), (0x05, 0x04, 60)] {
            let mut bytes = [0x4c; 64];
            bytes[..12].copy_from_slice(&lms_header(1, lms_type, ots_type));
            for len in 0..=bytes.len() {
                let result = TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &bytes[..len])]);
                if len == valid_len {
                    assert_eq!(result.unwrap().len(), 1, "{len}");
                } else {
                    assert_eq!(
                        result.unwrap_err(),
                        KeySetError::InvalidPublicKeyLength(Algorithm::LmsHss),
                        "{len}"
                    );
                }
            }
        }
        // Without a valid header, no length is accepted.
        let bytes = [0x4c; 64];
        for len in 0..=bytes.len() {
            let result = TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &bytes[..len])]);
            assert_eq!(
                result.unwrap_err(),
                KeySetError::InvalidPublicKeyLength(Algorithm::LmsHss),
                "{len}"
            );
        }
        assert_eq!(lms::PUBLIC_KEY_LENS, [52, 60]);
    }

    #[test]
    fn lms_key_length_must_match_its_typecode() {
        // 60 bytes with an M24 typecode (LMS_SHA256_M24_H5 0x0A / LMOTS_SHA256_N24_W8 0x08)
        // and 52 bytes with an M32 typecode (LMS_SHA256_M32_H5 0x05 / LMOTS_SHA256_N32_W8
        // 0x04): each length is one of the two accepted ones, but not its typecode's.
        for (lms_type, ots_type, len) in [(0x0Au32, 0x08u32, 60usize), (0x05, 0x04, 52)] {
            let mut pk = [0x11u8; 60];
            pk[..12].copy_from_slice(&lms_header(1, lms_type, ots_type));
            let pk = &pk[..len];
            assert_eq!(
                TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, pk)]).unwrap_err(),
                KeySetError::InvalidPublicKeyLength(Algorithm::LmsHss),
                "LMS typecode {lms_type:#x}, {len} bytes"
            );
            assert_eq!(lms::check_public_key(pk), Err(Error::InvalidPublicKey));
        }
        // The matching lengths are accepted.
        for (lms_type, ots_type, len) in [(0x0Au32, 0x08u32, 52usize), (0x05, 0x04, 60)] {
            let mut pk = [0x11u8; 60];
            pk[..12].copy_from_slice(&lms_header(1, lms_type, ots_type));
            assert_eq!(
                TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &pk[..len])])
                    .unwrap()
                    .len(),
                1
            );
        }
        // L outside 1..=8 or an unknown LMS typecode are refused too; the LMS policies
        // are not: W2 (outside them), L = 3..=8 (above MAX_HSS_LEVELS) and m != n pass here
        // and are refused when verifying.
        for (levels, lms_type, ots_type, ok) in [
            (0u32, 0x05u32, 0x04u32, false),
            (9, 0x05, 0x04, false),
            (u32::MAX, 0x05, 0x04, false),
            (1, 0x04, 0x04, false),
            (1, 0x0F, 0x04, false),
            (1, 0x05, 0x02, true),
            (3, 0x05, 0x04, true),
            (8, 0x05, 0x04, true),
            (1, 0x05, 0x08, true),
        ] {
            let mut pk = [0x11u8; 60];
            pk[..12].copy_from_slice(&lms_header(levels, lms_type, ots_type));
            let result = TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &pk)]);
            assert_eq!(
                result.is_ok(),
                ok,
                "L {levels}, LMS {lms_type:#x}, OTS {ots_type:#x}"
            );
        }
    }

    #[test]
    fn wrong_length_key_id_is_invalid_key_id() {
        let keys = TrustedKeys::<1>::new(&[key(Algorithm::LmsHss, &LMS_PK_A)]).unwrap();
        let id = key_id_of(&LMS_PK_A);
        assert_eq!(keys.find(&id[..KEY_ID_LEN - 1]), Err(Error::InvalidKeyId));
        assert_eq!(keys.find(&[]), Err(Error::InvalidKeyId));
        let mut long = [0u8; KEY_ID_LEN + 1];
        long[..KEY_ID_LEN].copy_from_slice(&id);
        assert_eq!(keys.find(&long), Err(Error::InvalidKeyId));
        // A full-length SHA-256 is not a key ID either.
        let full: [u8; 32] = Sha256::digest(LMS_PK_A).into();
        assert_eq!(keys.find(&full), Err(Error::InvalidKeyId));
    }
}
