//! Post-quantum signature algorithms and their compile-time availability.

use crate::tlv::{TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG, TLV_MLDSA65_SIG};

/// A post-quantum signature algorithm keelsign images can carry.
///
/// Every variant is always present, whatever features are enabled, so images and key
/// sets can name an algorithm this build cannot verify; [`Algorithm::is_enabled`] says
/// whether it can.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-DSA-44 (FIPS 204). Needs the `ml-dsa` feature; verified by
    /// [`mldsa`](crate::mldsa).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204). Needs the `ml-dsa` feature; verified by
    /// [`mldsa`](crate::mldsa).
    MlDsa65,
    /// LMS/HSS (RFC 8554, NIST SP 800-208). Always enabled.
    LmsHss,
}

impl Algorithm {
    /// Every algorithm, in TLV-ID order.
    pub const ALL: &'static [Algorithm] =
        &[Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::LmsHss];

    /// The algorithm whose signature TLV has type `tlv_type`, if any.
    pub const fn from_tlv_type(tlv_type: u16) -> Option<Self> {
        match tlv_type {
            TLV_MLDSA44_SIG => Some(Algorithm::MlDsa44),
            TLV_MLDSA65_SIG => Some(Algorithm::MlDsa65),
            TLV_LMS_HSS_SIG => Some(Algorithm::LmsHss),
            _ => None,
        }
    }

    /// The TLV type carrying a signature of this algorithm.
    pub const fn tlv_type(self) -> u16 {
        match self {
            Algorithm::MlDsa44 => TLV_MLDSA44_SIG,
            Algorithm::MlDsa65 => TLV_MLDSA65_SIG,
            Algorithm::LmsHss => TLV_LMS_HSS_SIG,
        }
    }

    /// Whether this build can verify the algorithm: ML-DSA needs the `ml-dsa` feature;
    /// LMS/HSS is always enabled.
    pub const fn is_enabled(self) -> bool {
        match self {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 => cfg!(feature = "ml-dsa"),
            Algorithm::LmsHss => true,
        }
    }

    /// The encoded public-key length in bytes, when the algorithm fixes one:
    /// 1312 for ML-DSA-44 and 1952 for ML-DSA-65 (FIPS 204, Table 2). `None` for
    /// LMS/HSS, whose key length depends on its parameter set.
    pub const fn public_key_len(self) -> Option<usize> {
        match self {
            Algorithm::MlDsa44 => Some(1312),
            Algorithm::MlDsa65 => Some(1952),
            Algorithm::LmsHss => None,
        }
    }
}
