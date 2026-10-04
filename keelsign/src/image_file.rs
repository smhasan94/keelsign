//! Loading MCUboot images, computing their digest and editing the unprotected TLV area
//! (see `docs/signing.md`).
//!
//! `sign` never touches the bytes the image digest `M` covers (header, body and
//! protected TLV area): [`rebuild`] copies them verbatim and appends a new unprotected
//! TLV area built from [`UnprotectedArea`].

use crate::error::Error;
use crate::keyfile::{self, ReadError};
use keelsign_verify::image::{IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH, Image, TLV_INFO_MAGIC};
use keelsign_verify::tlv::KEELSIGN_TLV_RANGE;
use keelsign_verify::{DEFAULT_CHUNK_LEN, Policy, TrustedKeys};
use std::path::Path;

/// Largest image file read (64 MiB); MCUboot slots are far smaller.
pub const MAX_IMAGE_LEN: u64 = 64 << 20;

/// Largest TLV area `it_tlv_tot` can describe.
pub const MAX_TLV_AREA_LEN: usize = u16::MAX as usize;

/// The contents of the image file `path` (at most [`MAX_IMAGE_LEN`] bytes).
pub fn read_image(path: &Path) -> Result<Vec<u8>, Error> {
    let mut contents = keyfile::read_capped_with(path, MAX_IMAGE_LEN).map_err(|e| match e {
        ReadError::Io(source) => Error::Io {
            what: format!("read image {}", path.display()),
            source,
        },
        ReadError::TooLarge => Error::Image {
            path: path.to_path_buf(),
            reason: "larger than 64 MiB, so not an MCUboot image keelsign reads".into(),
        },
    })?;
    // Take the bytes out of the zeroizing buffer (images are not secret).
    Ok(std::mem::take(&mut *contents))
}

/// Parse `bytes` as an MCUboot image; a parse error is [`Error::Image`] for `path`.
pub fn parse<'a>(path: &Path, bytes: &'a [u8]) -> Result<Image<'a>, Error> {
    Image::parse(bytes).map_err(|e| Error::Image {
        path: path.to_path_buf(),
        reason: format!("not an MCUboot image keelsign reads: {e}"),
    })
}

/// The image digest `M`: SHA-256 over header, body and protected TLV area, as the device
/// computes it ([`keelsign_verify::image_digest`]).
pub fn digest(bytes: &[u8], image: &Image<'_>) -> Result<[u8; 32], Error> {
    let mut reader: &[u8] = bytes;
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    keelsign_verify::image_digest(&mut reader, image, &mut chunk)
        .map_err(|e| Error::Internal(format!("could not compute the image digest: {e}")))
}

/// Bytes after the unprotected TLV area (a slot trailer or padding).
pub fn trailing_bytes(bytes: &[u8], image: &Image<'_>) -> usize {
    usize::try_from(image.tlv_end())
        .map(|end| bytes.len().saturating_sub(end))
        .unwrap_or(0)
}

/// What [`precheck`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Precheck {
    /// Every image rule passes and the image has no post-quantum signature.
    Ready,
    /// The image is not an MCUboot image or breaks an image rule; the reason.
    Rejected(String),
    /// The image rules pass, but the image already has keelsign TLVs (or verification
    /// failed in some other way): the error.
    Other(String),
}

/// Run `keelsign_verify::verify` with an empty key set under [`Policy::PqOnly`].
///
/// It checks the image rules (parse, flags, keelsign TLVs in the protected area,
/// `SIG_PURE`, exactly one 32-byte `SHA256` TLV, `SEC_CNT`, digest equal to the `SHA256`
/// TLV) before the post-quantum half, so on an image without keelsign TLVs it returns
/// exactly `MissingPqSignature` when every rule passes.
pub fn precheck(bytes: &[u8]) -> Precheck {
    let keys = match TrustedKeys::<1>::new(&[]) {
        Ok(keys) => keys,
        Err(e) => return Precheck::Other(e.to_string()),
    };
    let mut reader: &[u8] = bytes;
    let mut tlv_buf = vec![0u8; bytes.len()];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    match keelsign_verify::verify(&mut reader, &keys, Policy::PqOnly, &mut tlv_buf, &mut chunk) {
        Err(keelsign_verify::Error::MissingPqSignature) => Precheck::Ready,
        Err(e @ (keelsign_verify::Error::Parse(_) | keelsign_verify::Error::Image(_))) => {
            Precheck::Rejected(e.to_string())
        }
        Err(e) => Precheck::Other(e.to_string()),
        // Unreachable with an empty key set; never treat it as ready.
        Ok(_) => Precheck::Other("verified against an empty key set".into()),
    }
}

/// An editable copy of an image's unprotected TLV area, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnprotectedArea {
    /// The TLVs as (type, value).
    pub tlvs: Vec<(u16, Vec<u8>)>,
}

impl UnprotectedArea {
    /// The unprotected TLVs of `image`, in order.
    pub fn from_image(image: &Image<'_>) -> Self {
        Self {
            tlvs: image
                .unprotected()
                .iter()
                .map(|tlv| (tlv.tlv_type, tlv.value.to_vec()))
                .collect(),
        }
    }

    /// Number of TLVs of the keelsign block (`0x4BA0..=0x4BAF`).
    pub fn keelsign_count(&self) -> usize {
        self.tlvs
            .iter()
            .filter(|(t, _)| KEELSIGN_TLV_RANGE.contains(t))
            .count()
    }

    /// Number of `ED25519` TLVs.
    pub fn ed25519_count(&self) -> usize {
        self.tlvs
            .iter()
            .filter(|(t, _)| *t == IMAGE_TLV_ED25519)
            .count()
    }

    /// Remove every TLV of the keelsign block; returns how many were removed.
    pub fn strip_keelsign(&mut self) -> usize {
        let before = self.tlvs.len();
        self.tlvs.retain(|(t, _)| !KEELSIGN_TLV_RANGE.contains(t));
        before - self.tlvs.len()
    }

    /// Remove every `ED25519` TLV and the `KEYHASH` immediately before it (MCUboot's
    /// pair); other `KEYHASH` TLVs (an RSA or ECDSA pair's) stay. Returns how many TLVs
    /// were removed.
    pub fn strip_ed25519_pairs(&mut self) -> usize {
        let before = self.tlvs.len();
        let mut kept: Vec<(u16, Vec<u8>)> = Vec::with_capacity(before);
        for (tlv_type, value) in std::mem::take(&mut self.tlvs) {
            if tlv_type == IMAGE_TLV_ED25519 {
                if kept.last().is_some_and(|(t, _)| *t == IMAGE_TLV_KEYHASH) {
                    kept.pop();
                }
                continue;
            }
            kept.push((tlv_type, value));
        }
        self.tlvs = kept;
        before - self.tlvs.len()
    }

    /// Append a TLV.
    pub fn push(&mut self, tlv_type: u16, value: Vec<u8>) {
        self.tlvs.push((tlv_type, value));
    }

    /// The area's length with its 4-byte info header: `it_tlv_tot`.
    pub fn encoded_len(&self) -> usize {
        self.tlvs.iter().fold(4usize, |n, (_, v)| {
            n.saturating_add(4).saturating_add(v.len())
        })
    }

    /// The encoded area: info header (magic `0x6907`, `it_tlv_tot`) and the TLVs, all
    /// little-endian. Fails with the would-be length if it exceeds 65,535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, usize> {
        let total = self.encoded_len();
        let tot = u16::try_from(total).map_err(|_| total)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&TLV_INFO_MAGIC.to_le_bytes());
        out.extend_from_slice(&tot.to_le_bytes());
        for (tlv_type, value) in &self.tlvs {
            // Each value is shorter than the whole area, which fits a u16.
            let len = u16::try_from(value.len()).map_err(|_| total)?;
            out.extend_from_slice(&tlv_type.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(value);
        }
        Ok(out)
    }
}

/// A new image: the bytes `M` covers (`..image.hashed_range().end`), copied verbatim,
/// followed by `unprotected` (an encoded TLV area).
pub fn rebuild(bytes: &[u8], image: &Image<'_>, unprotected: &[u8]) -> Result<Vec<u8>, Error> {
    let end = usize::try_from(image.hashed_range().end)
        .ok()
        .and_then(|end| bytes.get(..end))
        .ok_or_else(|| Error::Internal("the hashed range is outside the image".into()))?;
    let mut out = Vec::with_capacity(end.len() + unprotected.len());
    out.extend_from_slice(end);
    out.extend_from_slice(unprotected);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keelsign_verify::image::{IMAGE_TLV_RSA2048_PSS, IMAGE_TLV_SHA256};
    use keelsign_verify::tlv::{TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG};

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/images")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn types(area: &UnprotectedArea) -> Vec<u16> {
        area.tlvs.iter().map(|(t, _)| *t).collect()
    }

    #[test]
    fn rebuild_copies_the_hashed_prefix_verbatim() {
        for name in [
            "mcuboot-ed25519.bin",
            "keelsign-mldsa44-protected-tlvs.bin",
            "keelsign-hybrid-protected-tlvs.bin",
        ] {
            let bytes = fixture(name);
            let image = Image::parse(&bytes).expect("parse");
            let end = image.hashed_range().end as usize;

            // The same area rebuilds the same file.
            let area = UnprotectedArea::from_image(&image);
            let encoded = area.encode().expect("encode");
            assert_eq!(encoded, image.unprotected().bytes(), "{name}");
            let same = rebuild(&bytes, &image, &encoded).expect("rebuild");
            assert_eq!(same, bytes, "{name}");

            // A different area keeps the prefix byte-for-byte and the digest.
            let mut edited = area.clone();
            edited.strip_keelsign();
            edited.push(0x7777, vec![1, 2, 3]);
            let out = rebuild(&bytes, &image, &edited.encode().expect("encode")).expect("rb");
            assert_eq!(out[..end], bytes[..end], "{name}");
            let parsed = Image::parse(&out).expect("parse rebuilt");
            assert_eq!(parsed.hashed_range(), image.hashed_range());
            assert_eq!(parsed.tlv_end() as usize, out.len());
            assert_eq!(
                digest(&out, &parsed).expect("digest"),
                digest(&bytes, &image).expect("digest"),
                "{name}"
            );
            let last = parsed.unprotected().iter().last().expect("a TLV");
            assert_eq!((last.tlv_type, last.value), (0x7777, &[1u8, 2, 3][..]));
        }
    }

    #[test]
    fn strip_keelsign_removes_the_whole_block() {
        let mut area = UnprotectedArea::default();
        area.push(IMAGE_TLV_SHA256, vec![0; 32]);
        area.push(TLV_KEELSIGN_KEY_ID, vec![1; 16]);
        area.push(0x4BAF, vec![2]);
        area.push(TLV_LMS_HSS_SIG, vec![3; 8]);
        area.push(0x4B9F, vec![4]);
        area.push(0x4BB0, vec![5]);
        area.push(TLV_MLDSA44_SIG, vec![6; 8]);
        assert_eq!(area.keelsign_count(), 4);
        assert_eq!(area.strip_keelsign(), 4);
        assert_eq!(types(&area), [IMAGE_TLV_SHA256, 0x4B9F, 0x4BB0]);
        assert_eq!(area.keelsign_count(), 0);

        let bytes = fixture("keelsign-dual-pq-invalid.bin");
        let image = Image::parse(&bytes).expect("parse");
        let mut area = UnprotectedArea::from_image(&image);
        assert_eq!(area.strip_keelsign(), 3);
        assert_eq!(types(&area), [IMAGE_TLV_SHA256]);
    }

    #[test]
    fn strip_ed25519_removes_the_pair_not_other_keyhashes() {
        let mut area = UnprotectedArea::default();
        area.push(IMAGE_TLV_SHA256, vec![0; 32]);
        area.push(IMAGE_TLV_KEYHASH, vec![1; 32]);
        area.push(IMAGE_TLV_RSA2048_PSS, vec![2; 256]);
        area.push(IMAGE_TLV_KEYHASH, vec![3; 32]);
        area.push(IMAGE_TLV_ED25519, vec![4; 64]);
        area.push(IMAGE_TLV_ED25519, vec![5; 64]); // unpaired: no KEYHASH before it
        area.push(IMAGE_TLV_KEYHASH, vec![6; 32]); // unpaired: nothing after it
        assert_eq!(area.ed25519_count(), 2);
        assert_eq!(area.strip_ed25519_pairs(), 3);
        assert_eq!(
            area.tlvs,
            [
                (IMAGE_TLV_SHA256, vec![0; 32]),
                (IMAGE_TLV_KEYHASH, vec![1; 32]),
                (IMAGE_TLV_RSA2048_PSS, vec![2; 256]),
                (IMAGE_TLV_KEYHASH, vec![6; 32]),
            ]
        );

        let bytes = fixture("mcuboot-ed25519.bin");
        let image = Image::parse(&bytes).expect("parse");
        let mut area = UnprotectedArea::from_image(&image);
        assert_eq!(area.strip_ed25519_pairs(), 2);
        assert_eq!(types(&area), [IMAGE_TLV_SHA256]);

        let bytes = fixture("mcuboot-rsa2048.bin");
        let image = Image::parse(&bytes).expect("parse");
        let mut area = UnprotectedArea::from_image(&image);
        assert_eq!(area.strip_ed25519_pairs(), 0);
        assert_eq!(
            types(&area),
            [IMAGE_TLV_SHA256, IMAGE_TLV_KEYHASH, IMAGE_TLV_RSA2048_PSS]
        );
    }

    #[test]
    fn encode_refuses_tlv_tot_over_u16() {
        let mut area = UnprotectedArea::default();
        assert_eq!(area.encode(), Ok(vec![0x07, 0x69, 4, 0]));
        // 4 + 4 + 65,527 = 65,535: the largest area that fits.
        area.push(0x10, vec![0xAB; MAX_TLV_AREA_LEN - 8]);
        let encoded = area.encode().expect("fits");
        assert_eq!(encoded.len(), MAX_TLV_AREA_LEN);
        assert_eq!(encoded[..6], [0x07, 0x69, 0xFF, 0xFF, 0x10, 0x00]);
        // One more byte does not.
        area.tlvs[0].1.push(0);
        assert_eq!(area.encode(), Err(MAX_TLV_AREA_LEN + 1));
        // Nor does a sum of small TLVs past the limit.
        let mut many = UnprotectedArea::default();
        for _ in 0..17_000 {
            many.push(0x7000, vec![0]);
        }
        assert_eq!(many.encode(), Err(4 + 17_000 * 5));
    }

    #[test]
    fn precheck_classifies_images() {
        assert_eq!(precheck(&fixture("mcuboot-ed25519.bin")), Precheck::Ready);
        assert!(matches!(
            precheck(&fixture("keelsign-hybrid-bad-sha256.bin")),
            Precheck::Rejected(_)
        ));
        assert!(matches!(precheck(b"not an image"), Precheck::Rejected(_)));
        assert_eq!(
            precheck(&fixture("keelsign-mldsa44.bin")),
            Precheck::Other(keelsign_verify::Error::KeyNotTrusted.to_string())
        );
    }

    #[test]
    fn trailing_bytes_counts_padding() {
        let bytes = fixture("mcuboot-ed25519-padded.bin");
        let image = Image::parse(&bytes).expect("parse");
        assert_eq!(trailing_bytes(&bytes, &image), 8192 - 2315);
        let bytes = fixture("mcuboot-ed25519.bin");
        let image = Image::parse(&bytes).expect("parse");
        assert_eq!(trailing_bytes(&bytes, &image), 0);
    }
}
