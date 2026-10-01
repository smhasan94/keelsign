//! Reading an image from storage: the [`ImageReader`] trait, its in-memory
//! implementation for `&[u8]` and [`NorFlashReader`] over an `embedded-storage` NOR flash.
//!
//! [`Image::read_from`](crate::image::Image::read_from) and
//! [`image_digest`](crate::digest::image_digest) take any [`ImageReader`]. Offsets are
//! relative to the start of the image (the start of the slot), never absolute flash
//! addresses. Both read the image sequentially and in ascending order: first the header,
//! then the TLV info headers and areas ([`Image::read_from`](crate::image::Image::read_from)),
//! then the hashed bytes after the header, in chunks
//! ([`image_digest`](crate::digest::image_digest)).
//!
//! The reader is blocking. [`ImageReader::len`] is where the end of the slot's usable area
//! comes from: the caller supplies it (the slot size minus the boot trailer), and nothing is
//! read at or past it.

use core::fmt;

use embedded_storage::nor_flash::{NorFlashError, NorFlashErrorKind, ReadNorFlash};

/// Why reading from an [`ImageReader`] failed. Mirrors `embedded-storage`'s
/// [`NorFlashErrorKind`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The read runs past the reader's [`len`](ImageReader::len), or the reader's region
    /// does not fit the underlying storage.
    OutOfBounds,
    /// The storage refused the read's alignment.
    NotAligned,
    /// Any other storage error.
    Other,
}

impl From<NorFlashErrorKind> for ReadError {
    fn from(kind: NorFlashErrorKind) -> Self {
        match kind {
            NorFlashErrorKind::OutOfBounds => ReadError::OutOfBounds,
            NorFlashErrorKind::NotAligned => ReadError::NotAligned,
            _ => ReadError::Other,
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadError::OutOfBounds => "read is out of bounds",
            ReadError::NotAligned => "read is not aligned for the storage",
            ReadError::Other => "storage read failed",
        })
    }
}

impl core::error::Error for ReadError {}

/// Random-access, blocking reads of one image slot.
///
/// Offsets are relative to the start of the image. keelsign reads sequentially and in
/// ascending order (see the [module docs](self)).
pub trait ImageReader {
    /// Bytes readable from offset 0: the slot's usable area (the slot minus its trailer).
    fn len(&self) -> u32;

    /// Whether the reader has no readable bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` from image-relative `offset`, entirely or not at all. A read that runs
    /// past [`len`](ImageReader::len) is [`ReadError::OutOfBounds`].
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError>;
}

impl<R: ImageReader + ?Sized> ImageReader for &mut R {
    fn len(&self) -> u32 {
        (**self).len()
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError> {
        (**self).read(offset, buf)
    }
}

/// An image already in memory (or memory-mapped flash). Its length saturates at
/// `u32::MAX`.
impl ImageReader for &[u8] {
    fn len(&self) -> u32 {
        u32::try_from(<[u8]>::len(self)).unwrap_or(u32::MAX)
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError> {
        let start = usize::try_from(offset).map_err(|_| ReadError::OutOfBounds)?;
        let end = start.checked_add(buf.len()).ok_or(ReadError::OutOfBounds)?;
        let src = self.get(start..end).ok_or(ReadError::OutOfBounds)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// An image slot of `len` bytes at offset `base` of a NOR flash.
///
/// Only flashes that read single bytes (`READ_SIZE == 1`) are supported, which the nRF52840
/// NVMC and the RP2350 blocking flash driver do; anything else fails to compile. Bounds are
/// checked before the flash is touched: a read past `len` is [`ReadError::OutOfBounds`]
/// without a flash access, and the flash's own errors map to [`ReadError`] through
/// [`NorFlashErrorKind`].
#[derive(Debug)]
pub struct NorFlashReader<F> {
    flash: F,
    base: u32,
    len: u32,
}

impl<F: ReadNorFlash> NorFlashReader<F> {
    /// Compile-time check that `F` reads single bytes.
    const READ_SIZE_IS_ONE: () = assert!(
        F::READ_SIZE == 1,
        "NorFlashReader supports only flashes with READ_SIZE == 1"
    );

    /// A reader of the `len` bytes at flash offset `base`. `base + len` past the flash's
    /// capacity, or overflowing `u32`, is [`ReadError::OutOfBounds`].
    pub fn new(flash: F, base: u32, len: u32) -> Result<Self, ReadError> {
        let () = Self::READ_SIZE_IS_ONE;
        let end = base.checked_add(len).ok_or(ReadError::OutOfBounds)?;
        let end = usize::try_from(end).map_err(|_| ReadError::OutOfBounds)?;
        if end > flash.capacity() {
            return Err(ReadError::OutOfBounds);
        }
        Ok(NorFlashReader { flash, base, len })
    }

    /// The flash, back.
    pub fn into_inner(self) -> F {
        self.flash
    }
}

impl<F: ReadNorFlash> ImageReader for NorFlashReader<F> {
    fn len(&self) -> u32 {
        self.len
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError> {
        let n = u32::try_from(buf.len()).map_err(|_| ReadError::OutOfBounds)?;
        let end = offset.checked_add(n).ok_or(ReadError::OutOfBounds)?;
        if end > self.len {
            return Err(ReadError::OutOfBounds);
        }
        // `base + len` fits `u32` (checked in `new`) and `offset < end <= len`.
        let addr = self
            .base
            .checked_add(offset)
            .ok_or(ReadError::OutOfBounds)?;
        self.flash
            .read(addr, buf)
            .map_err(|e| ReadError::from(e.kind()))
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

    use std::vec;
    use std::vec::Vec;

    use super::mock::MockFlash;
    use super::*;
    use crate::digest::image_digest;
    use crate::image::Image;

    const IMAGE: &[u8] = include_bytes!("../../tests/fixtures/images/mcuboot-ed25519.bin");

    #[test]
    fn slice_reader_bounds() {
        let data: Vec<u8> = (0..=255u8).collect();
        let mut r: &[u8] = &data;
        assert_eq!(ImageReader::len(&r), 256);
        assert!(!ImageReader::is_empty(&r));
        let mut buf = [0u8; 16];
        r.read(0, &mut buf).unwrap();
        assert_eq!(buf, data[..16]);
        r.read(240, &mut buf).unwrap();
        assert_eq!(buf, data[240..]);
        // One byte past the end, far past it, and an offset whose end overflows.
        let before = buf;
        assert_eq!(r.read(241, &mut buf), Err(ReadError::OutOfBounds));
        assert_eq!(r.read(4096, &mut buf), Err(ReadError::OutOfBounds));
        assert_eq!(r.read(u32::MAX, &mut buf), Err(ReadError::OutOfBounds));
        assert_eq!(buf, before, "a failed read leaves the buffer untouched");
        // Empty reads are fine anywhere up to the end.
        r.read(256, &mut []).unwrap();
        assert_eq!(r.read(257, &mut []), Err(ReadError::OutOfBounds));
        let mut empty: &[u8] = &[];
        assert!(ImageReader::is_empty(&empty));
        assert_eq!(empty.read(0, &mut [0]), Err(ReadError::OutOfBounds));
        // Through `&mut R`.
        let by_ref = &mut r;
        assert_eq!(ImageReader::len(&by_ref), 256);
        by_ref.read(1, &mut buf[..1]).unwrap();
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn nor_flash_reader_rejects_base_len_past_capacity_and_reads_nothing_out_of_range() {
        let flash_bytes = vec![0xA5u8; 1024];
        let flash = MockFlash::new(&flash_bytes);
        assert_eq!(
            NorFlashReader::new(flash.clone(), 1000, 25).err(),
            Some(ReadError::OutOfBounds)
        );
        assert_eq!(
            NorFlashReader::new(flash.clone(), u32::MAX, 2).err(),
            Some(ReadError::OutOfBounds)
        );
        assert_eq!(
            NorFlashReader::new(flash.clone(), 0, 1025).err(),
            Some(ReadError::OutOfBounds)
        );
        let exact = NorFlashReader::new(flash.clone(), 1000, 24).unwrap();
        assert_eq!(exact.len(), 24);

        let mut r = NorFlashReader::new(flash, 512, 100).unwrap();
        let mut buf = [0u8; 10];
        r.read(90, &mut buf).unwrap();
        for (offset, n) in [(91, 10), (100, 1), (u32::MAX, 10)] {
            assert_eq!(
                r.read(offset, &mut buf[..n]),
                Err(ReadError::OutOfBounds),
                "{offset}+{n}"
            );
        }
        let flash = r.into_inner();
        // Only the in-range read reached the flash, at base + offset.
        assert_eq!(flash.reads, [(602, 10)]);
    }

    #[test]
    fn nor_flash_error_kinds_map_to_read_error() {
        for (kind, expected) in [
            (NorFlashErrorKind::OutOfBounds, ReadError::OutOfBounds),
            (NorFlashErrorKind::NotAligned, ReadError::NotAligned),
            (NorFlashErrorKind::Other, ReadError::Other),
        ] {
            assert_eq!(ReadError::from(kind), expected);
            let mut flash = MockFlash::new(IMAGE);
            flash.fail_at = Some(0);
            flash.fail_kind = kind;
            let len = u32::try_from(IMAGE.len()).unwrap();
            let mut r = NorFlashReader::new(flash, 0, len).unwrap();
            assert_eq!(r.read(0, &mut [0; 4]), Err(expected), "{kind:?}");
            // The flash's own errors come back through image_digest as Error::Read.
            let mut flash = MockFlash::new(IMAGE);
            flash.fail_at = Some(1);
            flash.fail_kind = kind;
            let mut r = NorFlashReader::new(flash, 0, len).unwrap();
            let image = Image::parse(IMAGE).unwrap();
            assert_eq!(
                image_digest(&mut r, &image, &mut [0; 64]),
                Err(crate::Error::Read(expected))
            );
        }
        let messages: Vec<std::string::String> = [
            ReadError::OutOfBounds,
            ReadError::NotAligned,
            ReadError::Other,
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
        assert!(messages[0] != messages[1] && messages[1] != messages[2]);
    }

    #[test]
    fn nor_flash_reader_digest_matches_slice_reader_at_offset() {
        // The image in the middle of a larger flash, like a DFU slot: reads are relative
        // to the slot, and the digest matches the in-memory one and the SHA256 TLV.
        let base = 0x3000usize;
        let mut flash_bytes = vec![0xFFu8; base + IMAGE.len() + 0x1000];
        flash_bytes[base..base + IMAGE.len()].copy_from_slice(IMAGE);
        let slot_len = u32::try_from(IMAGE.len() + 0x800).unwrap();
        let mut reader =
            NorFlashReader::new(MockFlash::new(&flash_bytes), base as u32, slot_len).unwrap();
        let mut tlv_buf = [0u8; 4096];
        let image = Image::read_from(&mut reader, &mut tlv_buf).unwrap();
        let mut chunk = [0u8; crate::digest::DEFAULT_CHUNK_LEN];
        let from_flash = image_digest(&mut reader, &image, &mut chunk).unwrap();
        let mut slice: &[u8] = IMAGE;
        let from_slice = image_digest(&mut slice, &image, &mut chunk).unwrap();
        assert_eq!(from_flash, from_slice);
        let sha256_tlv = image
            .unprotected()
            .pairs()
            .find(|(t, _)| *t == crate::image::IMAGE_TLV_SHA256)
            .unwrap()
            .1;
        assert_eq!(from_flash.as_slice(), sha256_tlv);
        // Nothing before the slot or past it was read.
        let flash = reader.into_inner();
        assert!(flash.reads.iter().all(|&(addr, n)| {
            addr as usize >= base && addr as usize + n <= base + slot_len as usize
        }));
    }
}

/// Test doubles shared by the reader, digest and image tests.
#[cfg(test)]
pub(crate) mod mock {
    #![allow(clippy::indexing_slicing)]

    use std::vec::Vec;

    use embedded_storage::nor_flash::{ErrorType, NorFlashErrorKind, ReadNorFlash};

    use super::{ImageReader, ReadError};

    /// An in-memory NOR flash that records every read `(address, length)` and fails the
    /// read with index `fail_at` (counting from 0) with `fail_kind`.
    #[derive(Clone, Debug)]
    pub(crate) struct MockFlash<'a> {
        pub(crate) data: &'a [u8],
        pub(crate) reads: Vec<(u32, usize)>,
        pub(crate) fail_at: Option<usize>,
        pub(crate) fail_kind: NorFlashErrorKind,
    }

    impl<'a> MockFlash<'a> {
        pub(crate) fn new(data: &'a [u8]) -> Self {
            MockFlash {
                data,
                reads: Vec::new(),
                fail_at: None,
                fail_kind: NorFlashErrorKind::Other,
            }
        }
    }

    impl ErrorType for MockFlash<'_> {
        type Error = NorFlashErrorKind;
    }

    impl ReadNorFlash for MockFlash<'_> {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let call = self.reads.len();
            self.reads.push((offset, bytes.len()));
            if self.fail_at == Some(call) {
                return Err(self.fail_kind);
            }
            let start = offset as usize;
            let src = self
                .data
                .get(start..start + bytes.len())
                .ok_or(NorFlashErrorKind::OutOfBounds)?;
            bytes.copy_from_slice(src);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.data.len()
        }
    }

    /// Wraps an [`ImageReader`]: records every read `(offset, length)` and fails the read
    /// with index `fail_at` (counting from 0) with `error`.
    pub(crate) struct Recording<R> {
        pub(crate) inner: R,
        pub(crate) reads: Vec<(u32, usize)>,
        pub(crate) fail_at: Option<usize>,
        pub(crate) error: ReadError,
    }

    impl<R: ImageReader> Recording<R> {
        pub(crate) fn new(inner: R) -> Self {
            Recording {
                inner,
                reads: Vec::new(),
                fail_at: None,
                error: ReadError::Other,
            }
        }

        pub(crate) fn failing_at(inner: R, call: usize) -> Self {
            Recording {
                fail_at: Some(call),
                ..Recording::new(inner)
            }
        }
    }

    impl<R: ImageReader> ImageReader for Recording<R> {
        fn len(&self) -> u32 {
            self.inner.len()
        }

        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError> {
            let call = self.reads.len();
            self.reads.push((offset, buf.len()));
            if self.fail_at == Some(call) {
                return Err(self.error);
            }
            self.inner.read(offset, buf)
        }
    }
}
