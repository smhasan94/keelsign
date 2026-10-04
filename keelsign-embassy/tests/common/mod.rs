//! Host test doubles: an in-memory NOR flash that logs every operation and can lose
//! power, the test partition layout and updater constructors.

// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    dead_code
)]

use std::cell::RefCell;

use embassy_embedded_hal::flash::partition::BlockingPartition;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embedded_storage::nor_flash::{ErrorType, NorFlash, NorFlashErrorKind, ReadNorFlash};
use embedded_storage_async::nor_flash::{
    NorFlash as AsyncNorFlash, ReadNorFlash as AsyncReadNorFlash,
};
use keelsign_embassy::{
    BlockingUpdater, Config, Ed25519Key, Error, FirmwareUpdaterConfig, Layout, TrustedKey, Updater,
    VerifiedImage,
};
use policy_kat::{Case, Expect};

/// State partition: 4 KiB at 0.
pub const STATE_OFFSET: u32 = 0;
pub const STATE_LEN: u32 = 0x1000;
/// DFU partition: 256 KiB right after it.
pub const DFU_OFFSET: u32 = 0x1000;
pub const DFU_LEN: u32 = 0x4_0000;
/// The whole flash.
pub const FLASH_SIZE: usize = 0x4_1000;
pub const ERASE_SIZE: usize = 4096;
pub const WRITE_SIZE: usize = 4;

/// embassy-boot's state magics (an erased state reads as `Boot`).
pub const SWAP_MAGIC: u8 = 0xF0;
pub const BOOT_MAGIC: u8 = 0xD0;

/// One flash operation, at absolute flash addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Read { addr: u32, len: usize },
    Write { addr: u32, len: usize },
    Erase { from: u32, to: u32 },
}

impl Op {
    /// Whether the operation changes the flash.
    pub fn mutates(&self) -> bool {
        !matches!(self, Op::Read { .. })
    }

    /// The byte range the operation covers.
    pub fn range(&self) -> (u32, u32) {
        match *self {
            Op::Read { addr, len } | Op::Write { addr, len } => (addr, addr + len as u32),
            Op::Erase { from, to } => (from, to),
        }
    }
}

/// An in-memory NOR flash (`READ_SIZE` 1) of `SIZE` bytes with `ERASE`-byte pages and
/// `WRITE`-byte writes. It logs every operation, refuses writes to bytes that are not
/// erased, and after `freeze_after` writes and erases loses power: every later write or
/// erase fails and changes nothing (a reset between two operations).
#[derive(Clone, Debug)]
pub struct MockFlash<const SIZE: usize, const ERASE: usize, const WRITE: usize> {
    pub mem: Vec<u8>,
    pub ops: Vec<Op>,
    pub freeze_after: Option<usize>,
    mutations: usize,
}

/// The flash of the tests' layout.
pub type Flash = MockFlash<FLASH_SIZE, ERASE_SIZE, WRITE_SIZE>;

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> MockFlash<SIZE, ERASE, WRITE> {
    /// An erased flash.
    pub fn new() -> Self {
        Self {
            mem: vec![0xFF; SIZE],
            ops: Vec::new(),
            freeze_after: None,
            mutations: 0,
        }
    }

    /// Writes and erases so far, including refused ones.
    pub fn mutations(&self) -> usize {
        self.mutations
    }

    /// Restores power: writes and erases work again.
    pub fn power_on(&mut self) {
        self.freeze_after = None;
    }

    fn may_mutate(&mut self) -> Result<(), NorFlashErrorKind> {
        let n = self.mutations;
        self.mutations += 1;
        match self.freeze_after {
            Some(limit) if n >= limit => Err(NorFlashErrorKind::Other),
            _ => Ok(()),
        }
    }

    fn do_read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), NorFlashErrorKind> {
        self.ops.push(Op::Read {
            addr: offset,
            len: bytes.len(),
        });
        let start = offset as usize;
        let src = self
            .mem
            .get(start..start + bytes.len())
            .ok_or(NorFlashErrorKind::OutOfBounds)?;
        bytes.copy_from_slice(src);
        Ok(())
    }

    fn do_write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), NorFlashErrorKind> {
        self.ops.push(Op::Write {
            addr: offset,
            len: bytes.len(),
        });
        if !(offset as usize).is_multiple_of(WRITE) || !bytes.len().is_multiple_of(WRITE) {
            return Err(NorFlashErrorKind::NotAligned);
        }
        let start = offset as usize;
        if start + bytes.len() > SIZE {
            return Err(NorFlashErrorKind::OutOfBounds);
        }
        self.may_mutate()?;
        let dst = &mut self.mem[start..start + bytes.len()];
        if dst.iter().any(|&b| b != 0xFF) {
            panic!("write to {offset:#x} over bytes that are not erased");
        }
        dst.copy_from_slice(bytes);
        Ok(())
    }

    fn do_erase(&mut self, from: u32, to: u32) -> Result<(), NorFlashErrorKind> {
        self.ops.push(Op::Erase { from, to });
        if !(from as usize).is_multiple_of(ERASE)
            || !(to as usize).is_multiple_of(ERASE)
            || from > to
        {
            return Err(NorFlashErrorKind::NotAligned);
        }
        if to as usize > SIZE {
            return Err(NorFlashErrorKind::OutOfBounds);
        }
        self.may_mutate()?;
        self.mem[from as usize..to as usize].fill(0xFF);
        Ok(())
    }
}

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> ErrorType
    for MockFlash<SIZE, ERASE, WRITE>
{
    type Error = NorFlashErrorKind;
}

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> ReadNorFlash
    for MockFlash<SIZE, ERASE, WRITE>
{
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.do_read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        SIZE
    }
}

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> NorFlash
    for MockFlash<SIZE, ERASE, WRITE>
{
    const WRITE_SIZE: usize = WRITE;
    const ERASE_SIZE: usize = ERASE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.do_erase(from, to)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.do_write(offset, bytes)
    }
}

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> AsyncReadNorFlash
    for MockFlash<SIZE, ERASE, WRITE>
{
    const READ_SIZE: usize = 1;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.do_read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        SIZE
    }
}

impl<const SIZE: usize, const ERASE: usize, const WRITE: usize> AsyncNorFlash
    for MockFlash<SIZE, ERASE, WRITE>
{
    const WRITE_SIZE: usize = WRITE;
    const ERASE_SIZE: usize = ERASE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.do_erase(from, to)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.do_write(offset, bytes)
    }
}

/// An erased flash with `image` at the start of the DFU partition (not logged).
pub fn flash_with(image: &[u8]) -> Flash {
    let mut flash = Flash::new();
    place(&mut flash, image);
    flash
}

/// Puts `image` at the start of the DFU partition, as the update transfer would.
pub fn place(flash: &mut Flash, image: &[u8]) {
    assert!(
        image.len() <= DFU_LEN as usize,
        "image does not fit the DFU slot"
    );
    let start = DFU_OFFSET as usize;
    flash.mem[start..start + image.len()].copy_from_slice(image);
}

/// The first word of the state partition: the bootloader's magic.
pub fn state_word(flash: &Flash) -> [u8; 4] {
    let start = STATE_OFFSET as usize;
    flash.mem[start..start + 4].try_into().unwrap()
}

/// The flash shared by the blocking partitions.
pub type Shared = BlockingMutex<NoopRawMutex, RefCell<Flash>>;

/// A blocking partition of the shared flash.
pub type Part<'a> = BlockingPartition<'a, NoopRawMutex, Flash>;

/// The blocking updater over the tests' layout.
pub type Blocking<'a, 'k, const N: usize, const E: usize> =
    BlockingUpdater<'a, 'k, Part<'a>, Part<'a>, N, E>;

/// A blocking updater over the tests' layout of `flash`.
pub fn blocking_updater<'a, 'k, const N: usize, const E: usize>(
    flash: &'a Shared,
    aligned: &'a mut [u8],
    config: &Config<'k, N, E>,
) -> Result<Blocking<'a, 'k, N, E>, Error> {
    let dfu = BlockingPartition::new(flash, DFU_OFFSET, DFU_LEN);
    let state = BlockingPartition::new(flash, STATE_OFFSET, STATE_LEN);
    BlockingUpdater::new(FirmwareUpdaterConfig { dfu, state }, aligned, config)
}

/// Runs the blocking `verify_and_mark_updated` once over `flash` and returns its result
/// and the flash afterwards.
pub fn mark_blocking<'k, const N: usize, const E: usize>(
    flash: Flash,
    config: &Config<'k, N, E>,
) -> (Result<VerifiedImage<'k>, Error>, Flash) {
    let shared = Shared::new(RefCell::new(flash));
    let mut aligned = [0u8; WRITE_SIZE];
    let result = {
        let mut updater = blocking_updater(&shared, &mut aligned, config).unwrap();
        let mut tlv_buf = [0u8; 4096];
        let mut chunk = [0u8; keelsign_embassy::DEFAULT_CHUNK_LEN];
        updater.verify_and_mark_updated(&mut tlv_buf, &mut chunk)
    };
    (result, shared.into_inner().into_inner())
}

/// The trusted post-quantum key of a policy-matrix case.
pub fn pq_key<'a>(case: &Case<'a>) -> Option<TrustedKey<'a>> {
    case.algorithm.map(|algorithm| TrustedKey {
        algorithm,
        public_key: case.public_key,
    })
}

/// The Ed25519 test key every policy-matrix case trusts.
pub fn ed25519_keys() -> [Ed25519Key<'static>; 1] {
    [Ed25519Key {
        public_key: &policy_kat::ED25519_TEST_KEY,
    }]
}

/// The policy-matrix verdict of an updater result: keelsign-verify's result for
/// [`Error::Rejected`], and a test failure for the adapter's own errors.
pub fn verdict(result: &Result<VerifiedImage<'_>, Error>) -> Option<Expect> {
    match result {
        Ok(image) => Expect::of(&Ok(*image)),
        Err(Error::Rejected(e)) => Expect::of(&Err(*e)),
        Err(other) => panic!("unexpected adapter error {other:?}"),
    }
}

/// Every write and erase in `ops` lies inside the state partition.
pub fn mutations_only_in_state(ops: &[Op]) -> bool {
    ops.iter().filter(|op| op.mutates()).all(|op| {
        let (from, to) = op.range();
        (STATE_OFFSET..STATE_OFFSET + STATE_LEN).contains(&from) && to <= STATE_OFFSET + STATE_LEN
    })
}

/// The tests' partitions as an async [`Layout`].
pub const LAYOUT: Layout = Layout {
    dfu_offset: DFU_OFFSET,
    dfu_len: DFU_LEN,
    state_offset: STATE_OFFSET,
    state_len: STATE_LEN,
};

/// The flash shared by the async updater.
pub type AsyncShared = AsyncMutex<NoopRawMutex, Flash>;

/// The async updater over the tests' layout.
pub type Async<'a, 'k, const N: usize, const E: usize> =
    Updater<'a, 'a, 'k, NoopRawMutex, Flash, N, E>;

/// An async updater over the tests' layout of `flash`.
pub fn async_updater<'a, 'k, const N: usize, const E: usize>(
    flash: &'a AsyncShared,
    aligned: &'a mut [u8],
    config: &Config<'k, N, E>,
) -> Result<Async<'a, 'k, N, E>, Error> {
    Updater::new(flash, LAYOUT, aligned, config)
}

/// Runs the async `verify_and_mark_updated` once over `flash` (polled to completion) and
/// returns its result and the flash afterwards.
pub fn mark_async<'k, const N: usize, const E: usize>(
    flash: Flash,
    config: &Config<'k, N, E>,
) -> (Result<VerifiedImage<'k>, Error>, Flash) {
    let shared = AsyncShared::new(flash);
    let mut aligned = [0u8; WRITE_SIZE];
    let result = {
        let mut updater = async_updater(&shared, &mut aligned, config).unwrap();
        let mut tlv_buf = [0u8; 4096];
        let mut chunk = [0u8; keelsign_embassy::DEFAULT_CHUNK_LEN];
        embassy_futures::block_on(updater.verify_and_mark_updated(&mut tlv_buf, &mut chunk))
    };
    (result, shared.into_inner())
}

/// The writes and erases of `ops`, in order.
pub fn mutations(ops: &[Op]) -> Vec<Op> {
    ops.iter().copied().filter(Op::mutates).collect()
}
