//! keelsign TLV type IDs and format constants for the MCUboot TLV area.
//!
//! The image format, the signing mode and the rationale for every value here are
//! specified in [`docs/image-format.md`][spec]. In short:
//!
//! - keelsign owns the MCUboot vendor-reserved block [`KEELSIGN_TLV_RANGE`]
//!   (`0x4BA0..=0x4BAF`): four IDs are assigned, `0x4BA4..=0x4BAF` are reserved.
//! - Every keelsign TLV lives in the **unprotected** TLV area; [`verify`](crate::verify)
//!   rejects an image with any TLV of the keelsign block in the protected area (SHA-46).
//!   Verifiers must ignore TLV types they do not know, in both areas.
//! - An image carries exactly one key-ID TLV and exactly one post-quantum signature TLV.
//! - The post-quantum signature is over the 32-byte image digest `M`: SHA-256 over the
//!   image header, the image body and the protected TLV area (its info header included),
//!   the same bytes and the same value as MCUboot's `IMAGE_TLV_SHA256`.
//!
//! [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md

use core::ops::RangeInclusive;

/// The block of TLV types reserved for keelsign: `0x4BA0..=0x4BAF`.
///
/// It sits in MCUboot's vendor-reserved space (`xxA0..=xxFF` for every upper byte `xx`)
/// and avoids `0x00A0..=0x00FF`, where nRF Connect SDK already uses `0x00A0` and `0x00A1`
/// ([docs/image-format.md, TLV table][spec]). `0x4BA4..=0x4BAF` are reserved for future
/// keelsign TLVs.
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#tlv-table
pub const KEELSIGN_TLV_RANGE: RangeInclusive<u16> = 0x4BA0..=0x4BAF;

/// TLV carrying the signer's key ID: [`KEY_ID_LEN`] bytes, the first bytes of the
/// SHA-256 of the raw public key (see [`key_id_of`](crate::key_id_of)). Unprotected.
///
/// See [docs/image-format.md, Key ID][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#key-id
pub const TLV_KEELSIGN_KEY_ID: u16 = 0x4BA0;

/// TLV carrying a pure ML-DSA-44 (FIPS 204) signature over the image digest, with the
/// context string [`MLDSA_CONTEXT`]. 2,420 bytes. Unprotected.
///
/// See [docs/image-format.md, TLV table][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#tlv-table
pub const TLV_MLDSA44_SIG: u16 = 0x4BA1;

/// TLV carrying a pure ML-DSA-65 (FIPS 204) signature over the image digest, with the
/// context string [`MLDSA_CONTEXT`]. 3,309 bytes. Unprotected.
///
/// See [docs/image-format.md, TLV table][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#tlv-table
pub const TLV_MLDSA65_SIG: u16 = 0x4BA2;

/// TLV carrying an HSS signature (RFC 8554 §6, NIST SP 800-208; a single LMS tree is
/// HSS with `L = 1`) over the image digest. Its length follows from the public key's
/// parameter set. Unprotected.
///
/// See [docs/image-format.md, TLV table][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#tlv-table
pub const TLV_LMS_HSS_SIG: u16 = 0x4BA3;

/// Length in bytes of a key ID: SHA-256 truncated to 128 bits.
///
/// See [docs/image-format.md, Key ID][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#key-id
pub const KEY_ID_LEN: usize = 16;

/// The FIPS 204 context string of every keelsign ML-DSA signature (pure ML-DSA, never
/// HashML-DSA): `b"keelsign-mcuboot-image-v1"`.
///
/// It separates keelsign image signatures from any other use of the same ML-DSA key.
/// [`mldsa::verify`](crate::mldsa::verify) (SHA-44) passes it as the FIPS 204 context.
///
/// See [docs/image-format.md, ML-DSA context][spec].
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#ml-dsa-context
pub const MLDSA_CONTEXT: &[u8] = b"keelsign-mcuboot-image-v1";

/// The maximum post-quantum signature TLV length the verifier accepts: 3,924 bytes, an
/// HSS signature with two levels of LMS_SHA256_M32_H25 / LMOTS_SHA256_N32_W8, the largest
/// set the LMS/HSS parameter policy admits. ML-DSA-65 (3,309 bytes) and every other
/// accepted set are smaller.
///
/// The image parser (SHA-35) enforces it as a hard parse bound. It also sizes partitions
/// and buffers (see [docs/image-format.md, Sizes][spec]).
///
/// [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#sizes
pub const MAX_PQ_SIGNATURE_LEN: usize = 3_924;

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
        for &alg in Algorithm::ALL {
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

        // The final IDs (SHA-37), all inside the keelsign block.
        assert_eq!(
            [
                TLV_KEELSIGN_KEY_ID,
                TLV_MLDSA44_SIG,
                TLV_MLDSA65_SIG,
                TLV_LMS_HSS_SIG
            ],
            [0x4BA0, 0x4BA1, 0x4BA2, 0x4BA3]
        );
        assert_eq!(KEELSIGN_TLV_RANGE, 0x4BA0..=0x4BAF);
        for tlv in [
            TLV_KEELSIGN_KEY_ID,
            TLV_MLDSA44_SIG,
            TLV_MLDSA65_SIG,
            TLV_LMS_HSS_SIG,
        ] {
            assert!(KEELSIGN_TLV_RANGE.contains(&tlv), "{tlv:#06x}");
        }
        // MCUboot vendor-reserved: xxA0..=xxFF for every upper byte, never 0xFFFF
        // (IMAGE_TLV_ANY), and clear of the 0x00A0..=0x00FF block nRF Connect SDK uses.
        for tlv in KEELSIGN_TLV_RANGE {
            assert!((tlv & 0xFF) >= 0xA0, "{tlv:#06x} is not vendor-reserved");
            assert_ne!(tlv, 0xFFFF);
            assert_ne!(tlv >> 8, 0x00, "{tlv:#06x} is in the 0x00xx block");
        }
        assert_eq!(MLDSA_CONTEXT, b"keelsign-mcuboot-image-v1");
        // FIPS 204: a context string is at most 255 bytes.
        assert!(MLDSA_CONTEXT.len() <= 255);
    }

    /// Bytes of an HSS signature with `levels` levels of LMS with hash length `m`
    /// (= n), height `h` and LM-OTS W8 (RFC 8554 §4.5, §5.4, §6.2; p = 34 for n = 32,
    /// 26 for n = 24, RFC 8554 Table 1 and SP 800-208 Table 4).
    fn hss_w8_sig_len(m: usize, h: usize, levels: usize) -> usize {
        let p = match m {
            32 => 34,
            24 => 26,
            _ => panic!("unsupported m {m}"),
        };
        let lmots = 4 + m + p * m;
        let lms = 4 + lmots + 4 + h * m;
        let lms_pk = 4 + 4 + 16 + m;
        4 + levels * lms + (levels - 1) * lms_pk
    }

    #[test]
    fn max_pq_signature_len_is_hss2_h25_m32() {
        assert_eq!(hss_w8_sig_len(32, 25, 2), 3_924);
        assert_eq!(MAX_PQ_SIGNATURE_LEN, hss_w8_sig_len(32, 25, 2));
        // Every other accepted set fits: ML-DSA-44/65 (FIPS 204 Table 2) and LMS/HSS with
        // m in {24, 32}, H5..=H25 and L in {1, 2} (equal heights bound mixed ones).
        for len in [2_420, 3_309] {
            assert!(len < MAX_PQ_SIGNATURE_LEN, "{len}");
        }
        for m in [24, 32] {
            for h in [5, 10, 15, 20, 25] {
                for levels in [1, 2] {
                    assert!(hss_w8_sig_len(m, h, levels) <= MAX_PQ_SIGNATURE_LEN);
                }
            }
        }
        // Spot values from the Sizes table of docs/image-format.md.
        assert_eq!(hss_w8_sig_len(32, 10, 1), 1_456);
        assert_eq!(hss_w8_sig_len(32, 20, 1), 1_776);
        assert_eq!(hss_w8_sig_len(32, 10, 2), 2_964);
        assert_eq!(hss_w8_sig_len(24, 10, 1), 904);
        assert_eq!(hss_w8_sig_len(24, 20, 1), 1_144);
        assert_eq!(hss_w8_sig_len(24, 10, 2), 1_852);
        assert_eq!(hss_w8_sig_len(24, 20, 2), 2_332);
        assert_eq!(hss_w8_sig_len(32, 20, 2), 3_604);
        assert_eq!(hss_w8_sig_len(32, 25, 1), 1_936);
        assert_eq!(hss_w8_sig_len(24, 25, 1), 1_264);
        assert_eq!(hss_w8_sig_len(24, 25, 2), 2_572);
    }
}
