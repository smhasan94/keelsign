//! Image builders for the tests, as in `keelsign-verify/src/image.rs` (`test_util`).

use keelsign_verify::image::{IMAGE_HEADER_SIZE, IMAGE_MAGIC, TLV_INFO_MAGIC, TLV_PROT_INFO_MAGIC};

pub(crate) fn header_bytes(hdr_size: u16, protect_tlv_size: u16, img_size: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&IMAGE_MAGIC.to_le_bytes());
    h.extend_from_slice(&0x1000u32.to_le_bytes());
    h.extend_from_slice(&hdr_size.to_le_bytes());
    h.extend_from_slice(&protect_tlv_size.to_le_bytes());
    h.extend_from_slice(&img_size.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&[1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(h.len(), IMAGE_HEADER_SIZE);
    h
}

pub(crate) fn area_bytes(magic: u16, tlvs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, v) in tlvs {
        body.extend_from_slice(&t.to_le_bytes());
        body.extend_from_slice(&u16::try_from(v.len()).unwrap().to_le_bytes());
        body.extend_from_slice(v);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_le_bytes());
    out.extend(body);
    out
}

/// A 32-byte header, a 4-byte body and the given TLV areas.
pub(crate) fn synth(protected: Option<&[(u16, &[u8])]>, unprotected: &[(u16, &[u8])]) -> Vec<u8> {
    let prot = protected.map(|t| area_bytes(TLV_PROT_INFO_MAGIC, t));
    let prot_len = prot.as_ref().map_or(0, Vec::len);
    let mut d = header_bytes(32, u16::try_from(prot_len).unwrap(), 4);
    d.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    d.extend(prot.unwrap_or_default());
    d.extend(area_bytes(TLV_INFO_MAGIC, unprotected));
    d
}

pub(crate) fn set_u16(d: &mut [u8], at: usize, v: u16) {
    d[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
