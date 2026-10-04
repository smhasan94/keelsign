//! nRF helpers (feature `nrf`): the NVMC-based updater types and state-buffer lengths.
//!
//! The application enables its chip on embassy-nrf (for example `embassy-nrf/nrf52840`).
//! The NVMC is blocking only: [`Blocking`] is the usual choice (the upstream embassy-boot
//! nRF example uses the blocking updater too); [`Async`] wraps the NVMC in a
//! [`SyncFlash`] so the async updater can read it blockingly.

use core::cell::RefCell;

use embassy_embedded_hal::flash::partition::BlockingPartition;
use embassy_nrf::nvmc::Nvmc;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};

use crate::{BlockingUpdater, SyncFlash, Updater};

/// Length of the aligned state buffer of [`Blocking`] (the NVMC's `WRITE_SIZE`, 4).
pub const BLOCKING_STATE_BUF_LEN: usize = <Nvmc<'static> as NorFlash>::WRITE_SIZE;

/// Length of the aligned state buffer of [`Async`] (`max(WRITE_SIZE, READ_SIZE)` of the
/// NVMC, 4).
pub const ASYNC_STATE_BUF_LEN: usize = max(
    <Nvmc<'static> as NorFlash>::WRITE_SIZE,
    <Nvmc<'static> as ReadNorFlash>::READ_SIZE,
);

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// The NVMC shared by the blocking DFU and state partitions.
pub type SharedNvmc<'d> = BlockingMutex<NoopRawMutex, RefCell<Nvmc<'d>>>;

/// A blocking partition of the NVMC.
pub type NvmcPartition<'a, 'd> = BlockingPartition<'a, NoopRawMutex, Nvmc<'d>>;

/// The blocking updater over two partitions of the NVMC.
pub type Blocking<'a, 'd, 'k, const N: usize, const E: usize> =
    BlockingUpdater<'a, 'k, NvmcPartition<'a, 'd>, NvmcPartition<'a, 'd>, N, E>;

/// The NVMC, as the async updater shares it.
pub type SharedSyncNvmc<'d> = Mutex<NoopRawMutex, SyncFlash<Nvmc<'d>>>;

/// The async updater over the NVMC.
pub type Async<'a, 'd, 'k, const N: usize, const E: usize> =
    Updater<'a, 'a, 'k, NoopRawMutex, SyncFlash<Nvmc<'d>>, N, E>;

/// [`Blocking`] over the partitions of the linker script
/// ([`BlockingUpdater::from_linkerfile`]), with a state buffer of the right length.
#[cfg(target_os = "none")]
pub fn blocking_from_linkerfile<'a, 'd, 'k, const N: usize, const E: usize>(
    flash: &'a SharedNvmc<'d>,
    aligned: &'a mut [u8; BLOCKING_STATE_BUF_LEN],
    keelsign: &crate::Config<'k, N, E>,
) -> Result<Blocking<'a, 'd, 'k, N, E>, crate::Error> {
    BlockingUpdater::from_linkerfile(flash, aligned, keelsign)
}

/// [`Async`] over the partitions of the linker script ([`Updater::from_linkerfile`]),
/// with a state buffer of the right length.
#[cfg(target_os = "none")]
pub fn async_from_linkerfile<'a, 'd, 'k, const N: usize, const E: usize>(
    flash: &'a SharedSyncNvmc<'d>,
    aligned: &'a mut [u8; ASYNC_STATE_BUF_LEN],
    keelsign: &crate::Config<'k, N, E>,
) -> Result<Async<'a, 'd, 'k, N, E>, crate::Error> {
    Updater::from_linkerfile(flash, aligned, keelsign)
}
