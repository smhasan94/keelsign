//! [`BlockingUpdater`]: embassy-boot's blocking firmware updater, with keelsign
//! verification before the swap is requested.

use embassy_boot::{BlockingFirmwareUpdater, FirmwareUpdaterConfig, FirmwareUpdaterError, State};
use embedded_storage::nor_flash::NorFlash;
use keelsign_verify::{
    DefaultBackend, ImageReader, Policy, ReadError, TrustedKeys, VerifiedImage, verify_with,
};

use crate::config::Config;
use crate::error::{ConfigError, Error};
use crate::log;

/// embassy-boot's `BlockingFirmwareUpdater` that marks the DFU image for swap only after
/// keelsign-verify accepts it.
///
/// Build it like embassy-boot's updater, from a [`FirmwareUpdaterConfig`] (the DFU and
/// state partitions) and an aligned state buffer of the state flash's `WRITE_SIZE`
/// bytes, plus the device's [`Config`]. Then, once the new image is in the DFU slot:
///
/// ```ignore
/// let mut tlv_buf = [0u8; 4096];
/// let mut chunk = [0u8; keelsign_embassy::DEFAULT_CHUNK_LEN];
/// match updater.verify_and_mark_updated(&mut tlv_buf, &mut chunk) {
///     Ok(image) => cortex_m::peripheral::SCB::sys_reset(), // the bootloader swaps
///     Err(e) => { /* nothing was written; the current application keeps booting */ }
/// }
/// ```
///
/// There is no plain `mark_updated`: the swap is only requested through
/// [`verify_and_mark_updated`](Self::verify_and_mark_updated) or
/// [`verify_and_mark_updated_if`](Self::verify_and_mark_updated_if).
///
/// The DFU flash must read single bytes (`READ_SIZE == 1`, as the nRF52840 NVMC and the
/// RP2350 blocking flash do); anything else fails to compile.
pub struct BlockingUpdater<'d, 'k, DFU, STATE, const N: usize, const E: usize = 0>
where
    DFU: NorFlash,
    STATE: NorFlash,
{
    updater: BlockingFirmwareUpdater<'d, DFU, STATE>,
    dfu_len: u32,
    keys: TrustedKeys<'k, N, E>,
    policy: Policy,
    backend: DefaultBackend,
}

impl<'d, 'k, DFU, STATE, const N: usize, const E: usize> BlockingUpdater<'d, 'k, DFU, STATE, N, E>
where
    DFU: NorFlash,
    STATE: NorFlash,
{
    /// Compile-time check that the DFU flash reads single bytes.
    const DFU_READ_SIZE_IS_ONE: () = assert!(
        DFU::READ_SIZE == 1,
        "keelsign-embassy reads the DFU slot with READ_SIZE == 1 only"
    );

    /// An updater over `config`'s partitions, with `aligned` as embassy-boot's state
    /// buffer, verifying under `keelsign`.
    ///
    /// Fails before touching the flash with [`Error::KeySet`] if `keelsign`'s keys do not
    /// form a key set, [`ConfigError::AlignedBufferLen`] if `aligned` is not the state
    /// flash's `WRITE_SIZE` long and [`ConfigError::DfuSlotEmpty`] for an empty DFU
    /// partition.
    pub fn new(
        config: FirmwareUpdaterConfig<DFU, STATE>,
        aligned: &'d mut [u8],
        keelsign: &Config<'k, N, E>,
    ) -> Result<Self, Error> {
        let () = Self::DFU_READ_SIZE_IS_ONE;
        let keys = keelsign.trusted_keys()?;
        if aligned.len() != STATE::WRITE_SIZE {
            return Err(ConfigError::AlignedBufferLen.into());
        }
        let dfu_len = u32::try_from(config.dfu.capacity()).unwrap_or(u32::MAX);
        if dfu_len == 0 {
            return Err(ConfigError::DfuSlotEmpty.into());
        }
        Ok(Self {
            updater: BlockingFirmwareUpdater::new(config, aligned),
            dfu_len,
            keys,
            policy: keelsign.policy,
            backend: keelsign.backend,
        })
    }

    /// Verifies the image in the DFU slot under the configured policy and keys, reading
    /// the slot only (nothing is written). `tlv_buf` holds the TLV areas (4 KiB is
    /// enough for every keelsign image) and `chunk` is the hashing buffer
    /// ([`DEFAULT_CHUNK_LEN`](crate::DEFAULT_CHUNK_LEN) bytes is the usual size).
    pub fn verify(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
    ) -> Result<VerifiedImage<'k>, Error> {
        let mut reader = DfuReader {
            updater: &mut self.updater,
            len: self.dfu_len,
        };
        verify_with(
            &self.backend,
            &mut reader,
            &self.keys,
            self.policy,
            tlv_buf,
            chunk,
        )
        .map_err(Error::Rejected)
    }

    /// Verifies the DFU image ([`verify`](Self::verify)) and, if it is accepted, marks it
    /// for swap. See [`verify_and_mark_updated_if`](Self::verify_and_mark_updated_if).
    pub fn verify_and_mark_updated(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
    ) -> Result<VerifiedImage<'k>, Error> {
        self.verify_and_mark_updated_if(tlv_buf, chunk, |_| true)
    }

    /// Verifies the DFU image and, if `accept` agrees (an anti-rollback check on
    /// [`VerifiedImage::version`] or [`VerifiedImage::security_counter`], say), writes
    /// the swap magic to the state partition. The next reset makes the bootloader swap
    /// the image in.
    ///
    /// In order: [`Error::BadState`] if a swap is already pending (only `Boot`, `Revert`
    /// and `DfuDetach` allow a new one), [`Error::Rejected`] if keelsign-verify rejects
    /// the image, [`Error::NotAccepted`] if `accept` returns false. In all three cases
    /// nothing is written. [`Error::Flash`] is a flash failure; a reset at any point
    /// leaves the state `Boot` or `Swap`.
    pub fn verify_and_mark_updated_if(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
        accept: impl FnOnce(&VerifiedImage<'k>) -> bool,
    ) -> Result<VerifiedImage<'k>, Error> {
        let result = self.verify_then_mark(tlv_buf, chunk, accept);
        log::outcome(&result);
        result
    }

    fn verify_then_mark(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
        accept: impl FnOnce(&VerifiedImage<'k>) -> bool,
    ) -> Result<VerifiedImage<'k>, Error> {
        check_no_pending_swap(self.updater.get_state()?)?;
        let image = self.verify(tlv_buf, chunk)?;
        if !accept(&image) {
            return Err(Error::NotAccepted);
        }
        self.updater.mark_updated()?;
        Ok(image)
    }

    /// The bootloader state (embassy-boot's `get_state`).
    pub fn get_state(&mut self) -> Result<State, Error> {
        Ok(self.updater.get_state()?)
    }

    /// Confirms the running image (embassy-boot's `mark_booted`): call it once the
    /// application after a swap works, or the bootloader reverts it on the next reset.
    pub fn mark_booted(&mut self) -> Result<(), Error> {
        Ok(self.updater.mark_booted()?)
    }

    /// Asks the bootloader to enter DFU mode (embassy-boot's `mark_dfu`).
    pub fn mark_dfu(&mut self) -> Result<(), Error> {
        Ok(self.updater.mark_dfu()?)
    }

    /// Writes `data` to the DFU slot at `offset`, erasing pages as needed (embassy-boot's
    /// `write_firmware`).
    pub fn write_firmware(&mut self, offset: usize, data: &[u8]) -> Result<(), Error> {
        Ok(self.updater.write_firmware(offset, data)?)
    }

    /// Erases the whole DFU slot and returns it for writing (embassy-boot's
    /// `prepare_update`).
    pub fn prepare_update(&mut self) -> Result<&mut DFU, Error> {
        Ok(self.updater.prepare_update()?)
    }

    /// Reads the DFU slot at `offset` (embassy-boot's `read_dfu`).
    pub fn read_dfu(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Error> {
        Ok(self.updater.read_dfu(offset, buf)?)
    }
}

#[cfg(target_os = "none")]
impl<'d, 'k, F, const N: usize, const E: usize>
    BlockingUpdater<
        'd,
        'k,
        embassy_embedded_hal::flash::partition::BlockingPartition<
            'd,
            embassy_sync::blocking_mutex::raw::NoopRawMutex,
            F,
        >,
        embassy_embedded_hal::flash::partition::BlockingPartition<
            'd,
            embassy_sync::blocking_mutex::raw::NoopRawMutex,
            F,
        >,
        N,
        E,
    >
where
    F: NorFlash,
{
    /// An updater over the DFU and state partitions the linker script names
    /// (`__bootloader_dfu_start` / `_end`, `__bootloader_state_start` / `_end`), both on
    /// `flash` (embassy-boot's `FirmwareUpdaterConfig::from_linkerfile_blocking`).
    ///
    /// embassy-embedded-hal's `BlockingPartition::new` runs on the linker symbols *before*
    /// the adapter's checks: misaligned symbols panic inside embassy. Only
    /// [`BlockingUpdater::new`] rules embassy's assertions out; the remaining checks
    /// (buffer length, empty DFU slot, keys) still return [`Error`]s here.
    pub fn from_linkerfile(
        flash: &'d embassy_sync::blocking_mutex::Mutex<
            embassy_sync::blocking_mutex::raw::NoopRawMutex,
            core::cell::RefCell<F>,
        >,
        aligned: &'d mut [u8],
        keelsign: &Config<'k, N, E>,
    ) -> Result<Self, Error> {
        Self::new(
            FirmwareUpdaterConfig::from_linkerfile_blocking(flash, flash),
            aligned,
            keelsign,
        )
    }
}

/// `Ok` unless the state asks for a swap already.
pub(crate) fn check_no_pending_swap(state: State) -> Result<(), Error> {
    match state {
        State::Boot | State::Revert | State::DfuDetach => Ok(()),
        State::Swap => Err(Error::BadState),
    }
}

/// The DFU slot as an [`ImageReader`], through embassy-boot's `read_dfu`.
struct DfuReader<'u, 'd, DFU: NorFlash, STATE: NorFlash> {
    updater: &'u mut BlockingFirmwareUpdater<'d, DFU, STATE>,
    len: u32,
}

impl<DFU: NorFlash, STATE: NorFlash> ImageReader for DfuReader<'_, '_, DFU, STATE> {
    fn len(&self) -> u32 {
        self.len
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadError> {
        let n = u32::try_from(buf.len()).map_err(|_| ReadError::OutOfBounds)?;
        let end = offset.checked_add(n).ok_or(ReadError::OutOfBounds)?;
        if end > self.len {
            return Err(ReadError::OutOfBounds);
        }
        self.updater.read_dfu(offset, buf).map_err(|e| match e {
            FirmwareUpdaterError::Flash(kind) => ReadError::from(kind),
            FirmwareUpdaterError::Signature(_) | FirmwareUpdaterError::BadState => ReadError::Other,
        })
    }
}
