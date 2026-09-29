//! keelsign TLV type IDs in the MCUboot TLV area.
//!
//! All values here are **PROVISIONAL (SHA-37)**: the final IDs and their registration
//! are fixed by SHA-37 and documented in `docs/image-format.md`. Do not rely on them in
//! images you intend to keep.

/// TLV carrying the signer's key ID ([`KEY_ID_LEN`] bytes, see
/// [`key_id_of`](crate::key_id_of)).
///
/// PROVISIONAL (SHA-37).
pub const TLV_KEELSIGN_KEY_ID: u16 = 0x00A0;

/// TLV carrying an ML-DSA-44 (FIPS 204) signature.
///
/// PROVISIONAL (SHA-37).
pub const TLV_MLDSA44_SIG: u16 = 0x00A1;

/// TLV carrying an ML-DSA-65 (FIPS 204) signature.
///
/// PROVISIONAL (SHA-37).
pub const TLV_MLDSA65_SIG: u16 = 0x00A2;

/// TLV carrying an LMS/HSS (RFC 8554, SP 800-208) signature.
///
/// PROVISIONAL (SHA-37).
pub const TLV_LMS_HSS_SIG: u16 = 0x00A3;

/// Length in bytes of a key ID.
///
/// PROVISIONAL (SHA-37).
pub const KEY_ID_LEN: usize = 16;

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
    use crate::algorithm::Algorithm;

    #[test]
    fn every_pq_tlv_id_maps_to_its_algorithm_and_back() {
        let expected = [
            (TLV_MLDSA44_SIG, Algorithm::MlDsa44),
            (TLV_MLDSA65_SIG, Algorithm::MlDsa65),
            (TLV_LMS_HSS_SIG, Algorithm::LmsHss),
        ];
        for (tlv, alg) in expected {
            assert_eq!(Algorithm::from_tlv_type(tlv), Some(alg), "{tlv:#06x}");
            assert_eq!(alg.tlv_type(), tlv, "{alg:?}");
        }
        for alg in Algorithm::ALL {
            assert_eq!(Algorithm::from_tlv_type(alg.tlv_type()), Some(alg));
        }
        // Every other TLV type, the key-ID TLV included, maps to no algorithm.
        let mut mapped = 0;
        for tlv in 0..=u16::MAX {
            if let Some(alg) = Algorithm::from_tlv_type(tlv) {
                assert!(expected.contains(&(tlv, alg)), "{tlv:#06x} -> {alg:?}");
                mapped += 1;
            }
        }
        assert_eq!(mapped, expected.len());
        assert_eq!(Algorithm::from_tlv_type(TLV_KEELSIGN_KEY_ID), None);
        assert_eq!(KEY_ID_LEN, 16);
    }
}
