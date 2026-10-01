//! A reference parser for MCUboot images, used as the fuzzing oracle.
//!
//! It is deliberately independent of `keelsign_verify::image`: a plain restatement of the
//! parsing rules in that module's docs, in `u64` arithmetic with explicit checks, written
//! as a straight-line walk over the input instead of slices and checked splits. It is a
//! copy of the SHA-35 test oracle in `keelsign-verify/src/image.rs` (`tests::oracle`),
//! which the parser's own tests check it against; [`crate::check_parse_image`] checks the
//! parser against it on every fuzz input. A bug has to be made twice, in two different
//! styles, to go unnoticed.
//!
//! Only the constants come from `keelsign_verify` (magics, the PQ signature bound).

use keelsign_verify::image::{IMAGE_MAGIC, ParseError, TLV_INFO_MAGIC, TLV_PROT_INFO_MAGIC};
use keelsign_verify::tlv::MAX_PQ_SIGNATURE_LEN;

/// The post-quantum signature TLV types (`0x4BA1..=0x4BA3`), bounded by
/// [`MAX_PQ_SIGNATURE_LEN`].
const PQ_SIGNATURE_TYPES: core::ops::RangeInclusive<u16> = 0x4BA1..=0x4BA3;

/// One TLV as the reference parser sees it: (protected, type, value offset in the
/// input, value length).
pub type OracleTlv = (bool, u16, usize, usize);

/// The header fields as the reference parser decodes them: little-endian, by offset
/// (MCUboot `struct image_header`), independently of `Header::parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleHeader {
    /// Offset 4, `u32`.
    pub load_addr: u32,
    /// Offset 8, `u16`.
    pub hdr_size: u16,
    /// Offset 10, `u16`.
    pub protect_tlv_size: u16,
    /// Offset 12, `u32`.
    pub img_size: u32,
    /// Offset 16, `u32`.
    pub flags: u32,
    /// Offsets 20 and 21, `u8`.
    pub major: u8,
    pub minor: u8,
    /// Offset 22, `u16`.
    pub revision: u16,
    /// Offset 24, `u32`.
    pub build_num: u32,
}

/// What the reference parser predicts for a valid image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// The header fields.
    pub header: OracleHeader,
    /// End of the hashed region, `hdr_size + img_size + protect_tlv_size`.
    pub hashed_end: u64,
    /// End of the unprotected TLV area.
    pub tlv_end: u64,
    /// Every TLV, the protected area's first, in order.
    pub tlvs: Vec<OracleTlv>,
}

/// Predict `Image::parse(d)`: the error it must return, or the layout of the image.
pub fn parse(d: &[u8]) -> Result<Parsed, ParseError> {
    use ParseError::*;
    let len = d.len() as u64;
    let byte = |at: u64| d[at as usize];
    let u16_at = |at: u64| u16::from_le_bytes([byte(at), byte(at + 1)]);
    let u32_at = |at: u64| u32::from_le_bytes([byte(at), byte(at + 1), byte(at + 2), byte(at + 3)]);
    if len < 32 {
        return Err(Truncated);
    }
    if u32_at(0) != IMAGE_MAGIC {
        return Err(BadMagic);
    }
    let hdr = u64::from(u16_at(8));
    let prot = u64::from(u16_at(10));
    let img = u64::from(u32_at(12));
    if hdr < 32 {
        return Err(HeaderTooSmall);
    }
    let tlv_off = hdr + img;
    let hashed = tlv_off + prot;
    if tlv_off > u64::from(u32::MAX) || hashed > u64::from(u32::MAX) {
        return Err(SizeOverflow);
    }
    if tlv_off > len {
        return Err(Truncated);
    }
    let mut tlvs = Vec::new();
    let area = |off: u64, tot: u64, protected: bool, tlvs: &mut Vec<OracleTlv>| {
        if tot < 4 {
            return Err(LengthMismatch);
        }
        let end = off + tot;
        if end > u64::from(u32::MAX) {
            return Err(SizeOverflow);
        }
        if end > len {
            return Err(Truncated);
        }
        let mut pos = off + 4;
        while pos < end {
            if end - pos < 4 {
                return Err(LengthMismatch);
            }
            let t = u16_at(pos);
            let l = u64::from(u16_at(pos + 2));
            if pos + 4 + l > end {
                return Err(LengthMismatch);
            }
            if PQ_SIGNATURE_TYPES.contains(&t) && l > MAX_PQ_SIGNATURE_LEN as u64 {
                return Err(PqSignatureTooLong);
            }
            tlvs.push((protected, t, (pos + 4) as usize, l as usize));
            pos += 4 + l;
        }
        Ok(end)
    };
    if prot != 0 {
        if tlv_off + 4 > len {
            return Err(Truncated);
        }
        if u16_at(tlv_off) != TLV_PROT_INFO_MAGIC {
            return Err(BadTlvInfoMagic);
        }
        let tot = u64::from(u16_at(tlv_off + 2));
        if tot != prot {
            return Err(ProtectedSizeMismatch);
        }
        area(tlv_off, tot, true, &mut tlvs)?;
    } else {
        if tlv_off + 2 > len {
            return Err(Truncated);
        }
        if u16_at(tlv_off) == TLV_PROT_INFO_MAGIC {
            return Err(ProtectedSizeMismatch);
        }
    }
    if hashed + 4 > len {
        return Err(Truncated);
    }
    if u16_at(hashed) != TLV_INFO_MAGIC {
        return Err(BadTlvInfoMagic);
    }
    let tlv_end = area(hashed, u64::from(u16_at(hashed + 2)), false, &mut tlvs)?;
    let header = OracleHeader {
        load_addr: u32_at(4),
        hdr_size: u16_at(8),
        protect_tlv_size: u16_at(10),
        img_size: u32_at(12),
        flags: u32_at(16),
        major: byte(20),
        minor: byte(21),
        revision: u16_at(22),
        build_num: u32_at(24),
    };
    Ok(Parsed {
        header,
        hashed_end: hashed,
        tlv_end,
        tlvs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{set_u16, synth};
    use keelsign_verify::image::{IMAGE_TLV_SEC_CNT, IMAGE_TLV_SHA256, Image};

    /// SHA-39 TP1 (supporting): a TLV value that runs one byte past its area, the bug
    /// `fuzz/tp1-tlv-length-off-by-one.patch` injects into the parser, is
    /// `LengthMismatch` to the reference parser, with or without input bytes after the
    /// area; the parser agrees.
    #[test]
    fn one_byte_overrun_is_length_mismatch() {
        let good = synth(
            Some(&[(IMAGE_TLV_SEC_CNT, &[7, 0, 0, 0])]),
            &[(IMAGE_TLV_SHA256, &[0x5A; 32])],
        );
        let parsed = parse(&good).unwrap();
        assert_eq!(parsed.tlvs.len(), 2);
        assert_eq!(parsed.tlv_end, good.len() as u64);
        // The unprotected SHA256 TLV's length field: header 32 + body 4 + protected area
        // 12 + unprotected info 4 + TLV type 2.
        let len_at = 32 + 4 + 12 + 4 + 2;
        for trailing in [0usize, 1, 16] {
            let mut d = good.clone();
            set_u16(&mut d, len_at, 33);
            d.extend(std::iter::repeat_n(0xEE, trailing));
            assert_eq!(parse(&d), Err(ParseError::LengthMismatch), "+{trailing}");
            assert_eq!(
                Image::parse(&d).map(|_| ()),
                Err(ParseError::LengthMismatch),
                "+{trailing}"
            );
        }
        // The protected SEC_CNT TLV overrunning by one byte, into the unprotected area.
        let mut d = good.clone();
        set_u16(&mut d, 32 + 4 + 4 + 2, 5);
        assert_eq!(parse(&d), Err(ParseError::LengthMismatch));
        assert_eq!(
            Image::parse(&d).map(|_| ()),
            Err(ParseError::LengthMismatch)
        );
    }
}
