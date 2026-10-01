//! The image digest `M`: SHA-256 over the header, the body and the protected TLV area,
//! read from storage in caller-sized chunks.
//!
//! [`image_digest`] hashes the 32 header bytes kept by [`Image`], streams the rest of
//! the header (its padding up to `hdr_size`) and the body, offsets 32 up to the TLV
//! offset, through the caller's chunk buffer, then hashes the protected TLV area from the
//! copy [`Image`] parsed ([`TlvArea::bytes`](crate::image::TlvArea::bytes)). Neither the
//! header nor the protected area is re-read from storage, so the digest covers exactly
//! the header and protected TLVs that were parsed (the version and the security counter
//! an image policy reports; SHA-46). This is the value
//! MCUboot stores in the `SHA256` TLV (`bootutil_img_hash`, `image_validate.c` at
//! `a8ffd2c`) and the message keelsign's post-quantum signatures sign
//! ([docs/image-format.md][spec]).
//!
//! # RAM
//!
//! Peak RAM is bounded by the chunk buffer: `chunk.len()` bytes (the caller's, default
//! [`DEFAULT_CHUNK_LEN`]) plus the SHA-256 state (about 108 bytes: 32 bytes of chaining
//! value, a 64-byte block buffer, the block count and the buffer position) plus the
//! function's own frame. Nothing scales with the image size.
//!
//! [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::image::{IMAGE_HEADER_SIZE, Image};
use crate::reader::ImageReader;

/// Default chunk size: MCUboot's `BOOT_TMPBUF_SZ` (`bootutil_priv.h:86` at `a8ffd2c`),
/// the buffer MCUboot hashes an image through.
pub const DEFAULT_CHUNK_LEN: usize = 256;

/// SHA-256 of `image`'s [`hashed_range`](Image::hashed_range), read from `reader` in
/// pieces of at most `chunk.len()` bytes.
///
/// `image` must have been read from `reader` (by
/// [`Image::read_from`](crate::image::Image::read_from), or parsed from the same bytes):
/// the header is hashed from [`Image::raw_header`], only the body bytes
/// `32..tlv_offset` are read, in ascending order, and the protected TLV area (if any) is
/// hashed from [`Image::protected`]'s [`bytes`](crate::image::TlvArea::bytes). Compare
/// the result with the image's `SHA256` TLV, or use it as the message of the
/// post-quantum signature.
///
/// Errors: [`Error::ChunkBufferEmpty`] if `chunk` is empty, and [`Error::Read`] if a read
/// fails (the digest is then abandoned).
///
/// # Example
///
/// ```
/// use keelsign_verify::digest::{DEFAULT_CHUNK_LEN, image_digest};
/// use keelsign_verify::image::Image;
///
/// # const IMAGE: [u8; 48] = [
/// #     0x3D, 0xB8, 0xF3, 0x96, 0, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
/// #     1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD,
/// #     0x07, 0x69, 12, 0, 0x50, 0, 4, 0, 7, 0, 0, 0,
/// # ];
/// let mut slot: &[u8] = &IMAGE; // or a NorFlashReader over the DFU slot
/// let mut tlv_buf = [0u8; 64];
/// let image = Image::read_from(&mut slot, &mut tlv_buf)?;
/// let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
/// let digest = image_digest(&mut slot, &image, &mut chunk)?;
/// assert_eq!(digest.len(), 32);
/// # Ok::<(), keelsign_verify::Error>(())
/// ```
pub fn image_digest<R: ImageReader + ?Sized>(
    reader: &mut R,
    image: &Image<'_>,
    chunk: &mut [u8],
) -> Result<[u8; 32], Error> {
    if chunk.is_empty() {
        return Err(Error::ChunkBufferEmpty);
    }
    let mut hasher = Sha256::new();
    hasher.update(image.raw_header());
    // The body ends where the protected area starts (or, without one, where the hashed
    // range ends); the protected area is hashed from the parsed copy below.
    let protected = image.protected();
    let end = protected.map_or(image.hashed_range().end, |area| area.range().start);
    // `hdr_size >= 32`, so the body never ends inside the header.
    let mut offset = IMAGE_HEADER_SIZE as u32;
    while offset < end {
        let remaining = end - offset;
        let n = usize::try_from(remaining).map_or(chunk.len(), |r| r.min(chunk.len()));
        // `n <= chunk.len()`, so this always succeeds.
        let buf = chunk.get_mut(..n).ok_or(Error::ChunkBufferEmpty)?;
        reader.read(offset, buf)?;
        hasher.update(&*buf);
        // `n <= remaining`, so the sum stays within `end`.
        offset = offset.saturating_add(u32::try_from(n).unwrap_or(remaining));
    }
    if let Some(area) = protected {
        hasher.update(area.bytes());
    }
    Ok(hasher.finalize().into())
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

    use std::vec::Vec;

    use proptest::prelude::*;

    use super::*;
    use crate::image::{IMAGE_TLV_SHA256, TLV_HEADER_SIZE, TLV_INFO_SIZE};
    use crate::reader::ReadError;
    use crate::reader::mock::Recording;

    macro_rules! fixture {
        ($name:literal) => {
            (
                $name,
                include_bytes!(concat!("../../tests/fixtures/images/", $name)).as_slice(),
            )
        };
    }

    /// Every little-endian fixture image: the SHA-35 goldens, the 200 KB one (SHA-42) and
    /// the SHA-37 keelsign samples.
    const FIXTURES: [(&str, &[u8]); 12] = [
        fixture!("mcuboot-rsa2048.bin"),
        fixture!("mcuboot-ecdsa-p256.bin"),
        fixture!("mcuboot-ed25519.bin"),
        fixture!("mcuboot-ed25519-padded.bin"),
        fixture!("mcuboot-ed25519-200k.bin"),
        fixture!("keelsign-lms-m32-h5.bin"),
        fixture!("keelsign-hss2-m32-h5h5.bin"),
        fixture!("keelsign-lms-protected-tlvs.bin"),
        fixture!("keelsign-hybrid-ed25519-lms.bin"),
        fixture!("keelsign-mldsa44.bin"),
        fixture!("keelsign-mldsa65.bin"),
        fixture!("keelsign-dual-pq-invalid.bin"),
    ];

    const BIG: &str = "mcuboot-ed25519-200k.bin";

    fn expected(data: &[u8], image: &Image<'_>) -> [u8; 32] {
        let r = image.hashed_range();
        Sha256::digest(&data[r.start as usize..r.end as usize]).into()
    }

    fn sha256_tlv<'a>(image: &Image<'a>) -> &'a [u8] {
        image
            .unprotected()
            .pairs()
            .find(|(t, _)| *t == IMAGE_TLV_SHA256)
            .unwrap()
            .1
    }

    /// Where the streamed bytes end: the TLV offset (`hdr_size + img_size`), where the
    /// protected area, hashed from the parsed copy, starts.
    fn body_end(image: &Image<'_>) -> usize {
        image.header().tlv_offset().unwrap() as usize
    }

    fn digest_with(data: &[u8], chunk_len: usize) -> Result<[u8; 32], Error> {
        let image = Image::parse(data).unwrap();
        let mut reader = data;
        image_digest(&mut reader, &image, &mut vec_of(chunk_len))
    }

    fn vec_of(n: usize) -> Vec<u8> {
        std::vec![0u8; n]
    }

    #[test]
    fn default_chunk_len_is_256_and_only_caller_buffer_is_used() {
        assert_eq!(DEFAULT_CHUNK_LEN, 256);
        for (name, data) in FIXTURES {
            let image = Image::parse(data).unwrap();
            let mut reader = Recording::new(data);
            let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
            let digest = image_digest(&mut reader, &image, &mut chunk).unwrap();
            assert_eq!(digest, expected(data, &image), "{name}");
            // Every read goes through the caller's chunk and fills at most all of it; the
            // reads tile 32..tlv_offset (the protected area is hashed from the parsed
            // copy), so nothing else buffers the image.
            let end = body_end(&image);
            let mut next = 32usize;
            for &(offset, n) in &reader.reads {
                assert_eq!(offset as usize, next, "{name}");
                assert!((1..=DEFAULT_CHUNK_LEN).contains(&n), "{name}");
                next += n;
            }
            assert_eq!(next, end, "{name}");
            assert_eq!(reader.reads.len(), (end - 32).div_ceil(DEFAULT_CHUNK_LEN));
            // The last piece read is in the caller's buffer.
            let &(last_off, last_n) = reader.reads.last().unwrap();
            let last = &data[last_off as usize..last_off as usize + last_n];
            assert_eq!(&chunk[..last_n], last, "{name}");
        }
        // An empty chunk buffer is an error, not a panic or an endless loop.
        let data = FIXTURES[0].1;
        assert_eq!(digest_with(data, 0), Err(Error::ChunkBufferEmpty));
    }

    /// Image offsets `(start, end)` of every protected TLV value.
    fn protected_values(image: &Image<'_>) -> Vec<(usize, usize)> {
        let Some(area) = image.protected() else {
            return Vec::new();
        };
        let mut at = area.range().start as usize + TLV_INFO_SIZE;
        area.iter()
            .map(|tlv| {
                let start = at + TLV_HEADER_SIZE;
                at = start + tlv.value.len();
                (start, at)
            })
            .collect()
    }

    #[test]
    fn chunk_sizes_64_256_4096_agree_and_a_64_boundary_splits_a_protected_tlv() {
        let mut split = 0;
        for (name, data) in FIXTURES {
            let image = Image::parse(data).unwrap();
            let want = expected(data, &image);
            for chunk_len in [64, 256, 4096] {
                assert_eq!(digest_with(data, chunk_len), Ok(want), "{name} {chunk_len}");
            }
            assert_eq!(want.as_slice(), sha256_tlv(&image), "{name}");
            // A 64-byte chunk boundary (at 32 + 64k) strictly inside a protected TLV value.
            for (start, end) in protected_values(&image) {
                if (start + 1..end).any(|b| b >= 32 && (b - 32) % 64 == 0) {
                    split += 1;
                }
            }
        }
        assert!(
            split > 0,
            "no 64-byte chunk boundary falls inside a protected TLV"
        );
    }

    #[test]
    fn every_chunk_size_1_to_64_agrees() {
        for (name, data) in FIXTURES {
            let image = Image::parse(data).unwrap();
            let want = expected(data, &image);
            for chunk_len in 1..=64 {
                assert_eq!(digest_with(data, chunk_len), Ok(want), "{name} {chunk_len}");
            }
        }
    }

    #[test]
    fn digest_never_rereads_header_or_protected_area() {
        let mut with_protected = 0;
        for (name, data) in FIXTURES {
            let image = Image::parse(data).unwrap();
            let end = body_end(&image);
            for chunk_len in [1, 31, 32, 33, 256] {
                let mut reader = Recording::new(data);
                image_digest(&mut reader, &image, &mut vec_of(chunk_len)).unwrap();
                // No read below offset 32 (the header) or at or past the TLV offset (the
                // protected area and everything after it).
                assert!(
                    reader
                        .reads
                        .iter()
                        .all(|&(offset, n)| offset >= 32 && offset as usize + n <= end),
                    "{name} {chunk_len}"
                );
            }
            // The header comes from the parsed image: a reader whose header bytes differ
            // from the parsed ones still gives the parsed header's digest.
            let mut changed = data.to_vec();
            changed[20] ^= 0xFF; // iv_major
            let mut reader: &[u8] = &changed;
            let digest = image_digest(&mut reader, &image, &mut vec_of(256)).unwrap();
            assert_eq!(digest, expected(data, &image), "{name}");
            // So does the protected area: a reader whose protected TLV bytes (the info
            // header and every value) differ from the parsed copy still gives the parsed
            // copy's digest, the bytes the version and SEC_CNT were read from.
            if let Some(area) = image.protected() {
                with_protected += 1;
                let mut changed = data.to_vec();
                for b in &mut changed[range(area.range())] {
                    *b ^= 0xA5;
                }
                let mut reader: &[u8] = &changed;
                let digest = image_digest(&mut reader, &image, &mut vec_of(64)).unwrap();
                assert_eq!(digest, expected(data, &image), "{name}");
                assert_eq!(area.bytes(), &data[range(area.range())], "{name}");
            }
        }
        assert!(
            with_protected >= 5,
            "{with_protected} fixtures with a protected area"
        );
    }

    fn range(r: core::ops::Range<u32>) -> core::ops::Range<usize> {
        r.start as usize..r.end as usize
    }

    /// The number of reads a successful digest makes.
    fn read_count(data: &[u8], image: &Image<'_>, chunk_len: usize) -> usize {
        let mut reader = Recording::new(data);
        image_digest(&mut reader, image, &mut vec_of(chunk_len)).unwrap();
        reader.reads.len()
    }

    #[test]
    fn reader_failure_at_every_call_is_read_error() {
        for (name, data) in FIXTURES {
            let image = Image::parse(data).unwrap();
            for chunk_len in [1, 64, 256] {
                // Failing at every read is quadratic in the number of reads (each run hashes
                // everything before the failure): the 200 KB image gets every read of the
                // 256-byte chunks (800 runs), the others all three chunk sizes.
                if name == BIG && chunk_len != 256 {
                    continue;
                }
                let calls = read_count(data, &image, chunk_len);
                let errors = [
                    ReadError::OutOfBounds,
                    ReadError::NotAligned,
                    ReadError::Other,
                ];
                for k in 0..calls {
                    // Each error kind in turn, so that every kind is returned unchanged.
                    let error = errors[k % errors.len()];
                    let mut reader = Recording::failing_at(data, k);
                    reader.error = error;
                    assert_eq!(
                        image_digest(&mut reader, &image, &mut vec_of(chunk_len)),
                        Err(Error::Read(error)),
                        "{name} chunk {chunk_len} call {k}"
                    );
                    // The digest stops at the failing read.
                    assert_eq!(reader.reads.len(), k + 1);
                }
            }
        }
        // A reader shorter than the body fails with OutOfBounds, not a panic.
        let (_, data) = FIXTURES[0];
        let image = Image::parse(data).unwrap();
        let end = body_end(&image);
        let mut short: &[u8] = &data[..end - 1];
        assert_eq!(
            image_digest(&mut short, &image, &mut vec_of(64)),
            Err(Error::Read(ReadError::OutOfBounds))
        );
    }

    proptest! {
        #[test]
        fn random_chunk_sizes_and_images_agree(
            which in 0..FIXTURES.len(),
            chunk_len in 1usize..=8192,
        ) {
            let (name, data) = FIXTURES[which];
            let image = Image::parse(data).unwrap();
            let got = digest_with(data, chunk_len).unwrap();
            prop_assert_eq!(got, expected(data, &image), "{}", name);
            prop_assert_eq!(got.as_slice(), sha256_tlv(&image));
        }

        #[test]
        fn random_failures_never_panic(
            which in 0..FIXTURES.len(),
            chunk_len in 1usize..=4096,
            fail_at in 0usize..1024,
            cut in any::<prop::sample::Index>(),
        ) {
            let (_, data) = FIXTURES[which];
            let image = Image::parse(data).unwrap();
            // A failing read, and separately a slot cut short anywhere.
            let mut reader = Recording::failing_at(data, fail_at);
            let result = image_digest(&mut reader, &image, &mut vec_of(chunk_len));
            if fail_at < reader.reads.len() {
                prop_assert_eq!(result, Err(Error::Read(ReadError::Other)));
            } else {
                prop_assert_eq!(result, Ok(expected(data, &image)));
            }
            let cut = cut.index(data.len() + 1);
            let mut short: &[u8] = &data[..cut];
            let result = image_digest(&mut short, &image, &mut vec_of(chunk_len));
            if cut >= body_end(&image) {
                prop_assert_eq!(result, Ok(expected(data, &image)));
            } else {
                prop_assert_eq!(result, Err(Error::Read(ReadError::OutOfBounds)));
            }
        }
    }
}
