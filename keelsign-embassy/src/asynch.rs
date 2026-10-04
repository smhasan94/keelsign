//! [`Updater`]: embassy-boot's async firmware updater over one flash, with keelsign
//! verification before the swap is requested.

use embassy_boot::{FirmwareUpdater, State};
use embassy_embedded_hal::flash::partition::Partition;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage::nor_flash::ReadNorFlash;
use embedded_storage_async::nor_flash::{NorFlash, ReadNorFlash as AsyncReadNorFlash};
use keelsign_verify::{
    DefaultBackend, NorFlashReader, Policy, TrustedKeys, VerifiedImage, verify_with,
};

use crate::blocking::check_no_pending_swap;
use crate::config::Config;
use crate::error::{ConfigError, Error};
use crate::log;

/// Where the DFU and state partitions are on the flash, as byte offsets and lengths
/// (the bootloader's linker script `__bootloader_dfu_*` / `__bootloader_state_*`, made
/// relative to the flash base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Offset of the DFU partition.
    pub dfu_offset: u32,
    /// Length of the DFU partition.
    pub dfu_len: u32,
    /// Offset of the state partition.
    pub state_offset: u32,
    /// Length of the state partition.
    pub state_len: u32,
}

/// embassy-boot's async `FirmwareUpdater`, for one flash `F` shared through an
/// `embassy_sync` mutex, that marks the DFU image for swap only after keelsign-verify
/// accepts it.
///
/// Verification holds the mutex once, for the whole verify, and reads the DFU slot with
/// `F`'s *blocking* reads (keelsign-verify's reader is blocking; that is why `F` needs
/// both trait families, and why a blocking-only flash such as the nRF52840 NVMC goes in
/// a [`SyncFlash`](crate::SyncFlash)). The blocking reads must read single bytes
/// (`READ_SIZE == 1`, as the RP2350 flash does in every mode); anything else fails to
/// compile. Both partitions are on `F`: two-flash layouts need the blocking updater.
pub struct Updater<'a, 'd, 'k, M, F, const N: usize, const E: usize = 0>
where
    M: RawMutex,
    F: NorFlash + ReadNorFlash,
{
    flash: &'a Mutex<M, F>,
    updater: FirmwareUpdater<'d, Partition<'a, M, F>, Partition<'a, M, F>>,
    layout: Layout,
    keys: TrustedKeys<'k, N, E>,
    policy: Policy,
    backend: DefaultBackend,
}

impl<'a, 'd, 'k, M, F, const N: usize, const E: usize> Updater<'a, 'd, 'k, M, F, N, E>
where
    M: RawMutex,
    F: NorFlash + ReadNorFlash,
{
    /// An updater over the partitions `layout` names on `flash`, with `aligned` as
    /// embassy-boot's state buffer, verifying under `keelsign`.
    ///
    /// Fails before touching the flash with [`Error::KeySet`] if `keelsign`'s keys do not
    /// form a key set, and with an [`Error::Config`] if `aligned` is not
    /// `max(WRITE_SIZE, READ_SIZE)` of `F`'s async traits long
    /// ([`ConfigError::AlignedBufferLen`]), the DFU partition is empty
    /// ([`ConfigError::DfuSlotEmpty`]), a partition is not a multiple of the flash's
    /// read, write and erase sizes ([`ConfigError::DfuUnaligned`],
    /// [`ConfigError::StateUnaligned`]) or the partitions overlap
    /// ([`ConfigError::PartitionsOverlap`]).
    pub fn new(
        flash: &'a Mutex<M, F>,
        layout: Layout,
        aligned: &'d mut [u8],
        keelsign: &Config<'k, N, E>,
    ) -> Result<Self, Error> {
        let keys = keelsign.trusted_keys()?;
        check_layout::<F>(&layout, aligned.len())?;
        let dfu = Partition::new(flash, layout.dfu_offset, layout.dfu_len);
        let state = Partition::new(flash, layout.state_offset, layout.state_len);
        Ok(Self {
            flash,
            updater: FirmwareUpdater::new(
                embassy_boot::FirmwareUpdaterConfig { dfu, state },
                aligned,
            ),
            layout,
            keys,
            policy: keelsign.policy,
            backend: keelsign.backend,
        })
    }

    /// Verifies the image in the DFU slot under the configured policy and keys, reading
    /// the slot only (nothing is written), with the flash mutex held throughout.
    /// `tlv_buf` and `chunk` as for
    /// [`BlockingUpdater::verify`](crate::BlockingUpdater::verify).
    pub async fn verify(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
    ) -> Result<VerifiedImage<'k>, Error> {
        let mut flash = self.flash.lock().await;
        let mut reader =
            NorFlashReader::new(&mut *flash, self.layout.dfu_offset, self.layout.dfu_len)
                .map_err(|e| Error::Rejected(keelsign_verify::Error::Read(e)))?;
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
    pub async fn verify_and_mark_updated(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
    ) -> Result<VerifiedImage<'k>, Error> {
        self.verify_and_mark_updated_if(tlv_buf, chunk, |_| true)
            .await
    }

    /// As [`BlockingUpdater::verify_and_mark_updated_if`](crate::BlockingUpdater::verify_and_mark_updated_if):
    /// [`Error::BadState`], [`Error::Rejected`] and [`Error::NotAccepted`] write nothing;
    /// otherwise the swap magic is written to the state partition.
    pub async fn verify_and_mark_updated_if(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
        accept: impl FnOnce(&VerifiedImage<'k>) -> bool,
    ) -> Result<VerifiedImage<'k>, Error> {
        let result = self.verify_then_mark(tlv_buf, chunk, accept).await;
        log::outcome(&result);
        result
    }

    async fn verify_then_mark(
        &mut self,
        tlv_buf: &mut [u8],
        chunk: &mut [u8],
        accept: impl FnOnce(&VerifiedImage<'k>) -> bool,
    ) -> Result<VerifiedImage<'k>, Error> {
        check_no_pending_swap(self.updater.get_state().await?)?;
        let image = self.verify(tlv_buf, chunk).await?;
        if !accept(&image) {
            return Err(Error::NotAccepted);
        }
        self.updater.mark_updated().await?;
        Ok(image)
    }

    /// The bootloader state (embassy-boot's `get_state`).
    pub async fn get_state(&mut self) -> Result<State, Error> {
        Ok(self.updater.get_state().await?)
    }

    /// Confirms the running image (embassy-boot's `mark_booted`).
    pub async fn mark_booted(&mut self) -> Result<(), Error> {
        Ok(self.updater.mark_booted().await?)
    }

    /// Asks the bootloader to enter DFU mode (embassy-boot's `mark_dfu`).
    pub async fn mark_dfu(&mut self) -> Result<(), Error> {
        Ok(self.updater.mark_dfu().await?)
    }

    /// Writes `data` to the DFU slot at `offset` (embassy-boot's `write_firmware`).
    pub async fn write_firmware(&mut self, offset: usize, data: &[u8]) -> Result<(), Error> {
        Ok(self.updater.write_firmware(offset, data).await?)
    }

    /// Erases the whole DFU slot and returns it for writing (embassy-boot's
    /// `prepare_update`).
    pub async fn prepare_update(&mut self) -> Result<&mut Partition<'a, M, F>, Error> {
        Ok(self.updater.prepare_update().await?)
    }

    /// Reads the DFU slot at `offset` (embassy-boot's `read_dfu`, with the async reads).
    pub async fn read_dfu(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Error> {
        Ok(self.updater.read_dfu(offset, buf).await?)
    }
}

#[cfg(target_os = "none")]
impl<'a, 'k, F, const N: usize, const E: usize>
    Updater<'a, 'a, 'k, embassy_sync::blocking_mutex::raw::NoopRawMutex, F, N, E>
where
    F: NorFlash + ReadNorFlash,
{
    /// An updater over the DFU and state partitions the linker script names
    /// (`__bootloader_dfu_*`, `__bootloader_state_*`), both on `flash` (embassy-boot's
    /// `FirmwareUpdaterConfig::from_linkerfile`).
    pub fn from_linkerfile(
        flash: &'a Mutex<embassy_sync::blocking_mutex::raw::NoopRawMutex, F>,
        aligned: &'a mut [u8],
        keelsign: &Config<'k, N, E>,
    ) -> Result<Self, Error> {
        let config = embassy_boot::FirmwareUpdaterConfig::from_linkerfile(flash, flash);
        let layout = Layout {
            dfu_offset: config.dfu.offset(),
            dfu_len: config.dfu.size(),
            state_offset: config.state.offset(),
            state_len: config.state.size(),
        };
        Self::new(flash, layout, aligned, keelsign)
    }
}

/// Whether `value` is a multiple of every size in `sizes` (a zero size never divides).
fn multiple_of_all(value: u32, sizes: [usize; 3]) -> bool {
    usize::try_from(value).is_ok_and(|v| sizes.iter().all(|&s| s != 0 && v.is_multiple_of(s)))
}

/// The checks embassy-boot and embassy-embedded-hal would otherwise assert (panic) on.
fn check_layout<F: NorFlash>(layout: &Layout, aligned_len: usize) -> Result<(), ConfigError> {
    let read = <F as AsyncReadNorFlash>::READ_SIZE;
    if aligned_len != F::WRITE_SIZE.max(read) {
        return Err(ConfigError::AlignedBufferLen);
    }
    if layout.dfu_len == 0 {
        return Err(ConfigError::DfuSlotEmpty);
    }
    let sizes = [read, F::WRITE_SIZE, F::ERASE_SIZE];
    if !multiple_of_all(layout.dfu_offset, sizes) || !multiple_of_all(layout.dfu_len, sizes) {
        return Err(ConfigError::DfuUnaligned);
    }
    if !multiple_of_all(layout.state_offset, sizes) || !multiple_of_all(layout.state_len, sizes) {
        return Err(ConfigError::StateUnaligned);
    }
    let dfu_start = u64::from(layout.dfu_offset);
    let dfu_end = dfu_start + u64::from(layout.dfu_len);
    let state_start = u64::from(layout.state_offset);
    let state_end = state_start + u64::from(layout.state_len);
    if dfu_start < state_end && state_start < dfu_end {
        return Err(ConfigError::PartitionsOverlap);
    }
    Ok(())
}
