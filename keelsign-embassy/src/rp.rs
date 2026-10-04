//! RP2040 / RP235x helpers (feature `rp`): updater types over embassy-rp's `Flash` and
//! state-buffer lengths.
//!
//! The application enables its chip on embassy-rp (for example `embassy-rp/rp235xa`).
//! The flash reads single bytes blockingly in every mode, and four at a time with the
//! async (DMA) reads; the [`Updater`] verifies with the blocking reads and writes the
//! state with the async ones. `FLASH_SIZE` is the flash size the application gives
//! embassy-rp's `Flash` (for example 2 MiB on the Pico 2 W).

use core::cell::RefCell;

use embassy_embedded_hal::flash::partition::BlockingPartition;
use embassy_rp::flash::{
    ASYNC_READ_SIZE, Async as AsyncMode, Blocking as BlockingMode, Flash, WRITE_SIZE,
};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;

use crate::{BlockingUpdater, Updater};

/// Length of the aligned state buffer of [`Blocking`] (`WRITE_SIZE`, 1).
pub const BLOCKING_STATE_BUF_LEN: usize = WRITE_SIZE;

/// Length of the aligned state buffer of [`Async`] (`max(WRITE_SIZE, ASYNC_READ_SIZE)`,
/// 4).
pub const ASYNC_STATE_BUF_LEN: usize = if WRITE_SIZE > ASYNC_READ_SIZE {
    WRITE_SIZE
} else {
    ASYNC_READ_SIZE
};

/// The blocking-mode flash shared by the blocking DFU and state partitions.
pub type SharedBlockingFlash<'d, const FLASH_SIZE: usize> =
    BlockingMutex<NoopRawMutex, RefCell<Flash<'d, FLASH, BlockingMode, FLASH_SIZE>>>;

/// A blocking partition of the blocking-mode flash.
pub type FlashPartition<'a, 'd, const FLASH_SIZE: usize> =
    BlockingPartition<'a, NoopRawMutex, Flash<'d, FLASH, BlockingMode, FLASH_SIZE>>;

/// The blocking updater over two partitions of the blocking-mode flash.
pub type Blocking<'a, 'd, 'k, const FLASH_SIZE: usize, const N: usize, const E: usize> =
    BlockingUpdater<
        'a,
        'k,
        FlashPartition<'a, 'd, FLASH_SIZE>,
        FlashPartition<'a, 'd, FLASH_SIZE>,
        N,
        E,
    >;

/// The async-mode flash, as the async updater shares it.
pub type SharedAsyncFlash<'d, const FLASH_SIZE: usize> =
    Mutex<NoopRawMutex, Flash<'d, FLASH, AsyncMode, FLASH_SIZE>>;

/// The async updater over the async-mode flash.
pub type Async<'a, 'd, 'k, const FLASH_SIZE: usize, const N: usize, const E: usize> =
    Updater<'a, 'a, 'k, NoopRawMutex, Flash<'d, FLASH, AsyncMode, FLASH_SIZE>, N, E>;

/// [`Blocking`] over the partitions of the linker script
/// ([`BlockingUpdater::from_linkerfile`]), with a state buffer of the right length.
#[cfg(target_os = "none")]
pub fn blocking_from_linkerfile<
    'a,
    'd,
    'k,
    const FLASH_SIZE: usize,
    const N: usize,
    const E: usize,
>(
    flash: &'a SharedBlockingFlash<'d, FLASH_SIZE>,
    aligned: &'a mut [u8; BLOCKING_STATE_BUF_LEN],
    keelsign: &crate::Config<'k, N, E>,
) -> Result<Blocking<'a, 'd, 'k, FLASH_SIZE, N, E>, crate::Error> {
    BlockingUpdater::from_linkerfile(flash, aligned, keelsign)
}

/// [`Async`] over the partitions of the linker script ([`Updater::from_linkerfile`]),
/// with a state buffer of the right length.
#[cfg(target_os = "none")]
pub fn async_from_linkerfile<
    'a,
    'd,
    'k,
    const FLASH_SIZE: usize,
    const N: usize,
    const E: usize,
>(
    flash: &'a SharedAsyncFlash<'d, FLASH_SIZE>,
    aligned: &'a mut [u8; ASYNC_STATE_BUF_LEN],
    keelsign: &crate::Config<'k, N, E>,
) -> Result<Async<'a, 'd, 'k, FLASH_SIZE, N, E>, crate::Error> {
    Updater::from_linkerfile(flash, aligned, keelsign)
}
