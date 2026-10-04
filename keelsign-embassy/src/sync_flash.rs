//! [`SyncFlash`]: a blocking flash with the async NOR flash traits too.

use embedded_storage::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash as BlockingNorFlash,
    ReadNorFlash as BlockingReadNorFlash,
};
use embedded_storage_async::nor_flash::{
    MultiwriteNorFlash as AsyncMultiwriteNorFlash, NorFlash as AsyncNorFlash,
    ReadNorFlash as AsyncReadNorFlash,
};

/// Wraps a blocking flash and implements both the blocking and the async
/// `embedded-storage` NOR flash traits; the async ones run the blocking operation.
///
/// The nRF52840 NVMC is blocking only. embassy's `BlockingAsync` wrapper gives it the
/// async traits but hides the blocking ones, which [`Updater`](crate::Updater) needs to
/// read the DFU slot; `SyncFlash` keeps both.
#[derive(Debug)]
pub struct SyncFlash<T>(T);

impl<T> SyncFlash<T> {
    /// Wraps `flash`.
    pub const fn new(flash: T) -> Self {
        Self(flash)
    }

    /// The wrapped flash.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// The wrapped flash, back.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: ErrorType> ErrorType for SyncFlash<T> {
    type Error = T::Error;
}

impl<T: BlockingReadNorFlash> BlockingReadNorFlash for SyncFlash<T> {
    const READ_SIZE: usize = T::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl<T: BlockingNorFlash> BlockingNorFlash for SyncFlash<T> {
    const WRITE_SIZE: usize = T::WRITE_SIZE;
    const ERASE_SIZE: usize = T::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write(offset, bytes)
    }
}

impl<T: MultiwriteNorFlash> MultiwriteNorFlash for SyncFlash<T> {}

impl<T: BlockingReadNorFlash> AsyncReadNorFlash for SyncFlash<T> {
    const READ_SIZE: usize = T::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl<T: BlockingNorFlash> AsyncNorFlash for SyncFlash<T> {
    const WRITE_SIZE: usize = T::WRITE_SIZE;
    const ERASE_SIZE: usize = T::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write(offset, bytes)
    }
}

impl<T: MultiwriteNorFlash> AsyncMultiwriteNorFlash for SyncFlash<T> {}

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

    use embassy_futures::block_on;
    use embedded_storage::nor_flash::NorFlashErrorKind;

    use super::*;

    /// A 4 KiB blocking-only flash with 4-byte writes and 1 KiB pages that logs every
    /// operation.
    struct Blocking {
        mem: Vec<u8>,
        log: Vec<&'static str>,
    }

    impl ErrorType for Blocking {
        type Error = NorFlashErrorKind;
    }

    impl BlockingReadNorFlash for Blocking {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.log.push("read");
            let start = offset as usize;
            let src = self
                .mem
                .get(start..start + bytes.len())
                .ok_or(NorFlashErrorKind::OutOfBounds)?;
            bytes.copy_from_slice(src);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.mem.len()
        }
    }

    impl BlockingNorFlash for Blocking {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = 1024;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            self.log.push("erase");
            self.mem[from as usize..to as usize].fill(0xFF);
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            self.log.push("write");
            let start = offset as usize;
            self.mem[start..start + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    fn sizes<F: AsyncNorFlash + BlockingNorFlash>() -> [usize; 6] {
        [
            <F as AsyncReadNorFlash>::READ_SIZE,
            <F as AsyncNorFlash>::WRITE_SIZE,
            <F as AsyncNorFlash>::ERASE_SIZE,
            <F as BlockingReadNorFlash>::READ_SIZE,
            <F as BlockingNorFlash>::WRITE_SIZE,
            <F as BlockingNorFlash>::ERASE_SIZE,
        ]
    }

    #[test]
    fn sync_flash_forwards_both_trait_families() {
        assert_eq!(sizes::<SyncFlash<Blocking>>(), [1, 4, 1024, 1, 4, 1024]);
        let mut flash = SyncFlash::new(Blocking {
            mem: vec![0u8; 4096],
            log: Vec::new(),
        });
        assert_eq!(AsyncReadNorFlash::capacity(&flash), 4096);
        assert_eq!(BlockingReadNorFlash::capacity(&flash), 4096);

        // Async operations reach the blocking flash.
        block_on(AsyncNorFlash::erase(&mut flash, 0, 1024)).unwrap();
        block_on(AsyncNorFlash::write(&mut flash, 8, &[1, 2, 3, 4])).unwrap();
        let mut buf = [0u8; 6];
        block_on(AsyncReadNorFlash::read(&mut flash, 6, &mut buf)).unwrap();
        assert_eq!(buf, [0xFF, 0xFF, 1, 2, 3, 4]);

        // So do the blocking ones.
        BlockingNorFlash::erase(&mut flash, 1024, 2048).unwrap();
        BlockingNorFlash::write(&mut flash, 1024, &[9; 4]).unwrap();
        BlockingReadNorFlash::read(&mut flash, 1022, &mut buf).unwrap();
        // 1022..1024 is still erased from the async erase of the first page.
        assert_eq!(buf, [0xFF, 0xFF, 9, 9, 9, 9]);

        // Errors come back unchanged.
        assert_eq!(
            block_on(AsyncReadNorFlash::read(&mut flash, 4095, &mut buf)),
            Err(NorFlashErrorKind::OutOfBounds)
        );
        assert_eq!(
            BlockingReadNorFlash::read(&mut flash, 4095, &mut buf),
            Err(NorFlashErrorKind::OutOfBounds)
        );

        assert_eq!(flash.inner_mut().mem.len(), 4096);
        let inner = flash.into_inner();
        assert_eq!(
            inner.log,
            [
                "erase", "write", "read", "erase", "write", "read", "read", "read"
            ]
        );
    }
}
