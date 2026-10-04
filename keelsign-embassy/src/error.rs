//! Typed errors.

use core::fmt;

use embassy_boot::FirmwareUpdaterError;
use embedded_storage::nor_flash::NorFlashErrorKind;
use keelsign_verify::KeySetError;

/// Why an updater did not mark the DFU image for swap. Every variant except
/// [`Error::Flash`] (and a flash error inside [`Error::Rejected`]) is returned before
/// anything is written: the state partition is untouched and the bootloader keeps
/// booting the current application.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// keelsign-verify rejected the image in the DFU slot; the variant says why.
    Rejected(keelsign_verify::Error),
    /// The image verified, but the caller's `accept` check (anti-rollback, say) refused
    /// it.
    NotAccepted,
    /// The trusted keys of the [`Config`](crate::Config) do not form a key set.
    KeySet(KeySetError),
    /// The updater's buffers or partitions are unusable.
    Config(ConfigError),
    /// The state partition already asks for a swap: an update is pending. Only `Boot`,
    /// `Revert` and `DfuDetach` allow a new one (as embassy-boot's own checks).
    BadState,
    /// The flash failed: reading or writing the state partition, or the DFU partition
    /// in `write_firmware`, `prepare_update` and `read_dfu`. (A flash error while the DFU
    /// slot is verified is [`Error::Rejected`] with `keelsign_verify::Error::Read`.)
    Flash(NorFlashErrorKind),
}

/// What is wrong with an updater's buffers or partitions. Checked by `BlockingUpdater::new`
/// and `Updater::new` before embassy-boot sees them, so embassy's own assertions cannot
/// fire there. (The `from_linkerfile` constructors let embassy build the partitions from
/// the linker symbols first; see their docs.)
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The aligned state buffer has the wrong length (see the board `STATE_BUF_LEN`).
    AlignedBufferLen,
    /// The DFU partition's offset or length is not a multiple of the flash's read, write
    /// and erase sizes.
    DfuUnaligned,
    /// The state partition's offset or length is not a multiple of the flash's read,
    /// write and erase sizes.
    StateUnaligned,
    /// The DFU and state partitions overlap.
    PartitionsOverlap,
    /// The DFU partition is empty.
    DfuSlotEmpty,
    /// A partition's offset plus its length does not fit a `u32` flash offset.
    PartitionOutOfRange,
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Error::Config(e)
    }
}

impl From<keelsign_verify::Error> for Error {
    fn from(e: keelsign_verify::Error) -> Self {
        Error::Rejected(e)
    }
}

impl From<FirmwareUpdaterError> for Error {
    fn from(e: FirmwareUpdaterError) -> Self {
        match e {
            FirmwareUpdaterError::Flash(kind) => Error::Flash(kind),
            FirmwareUpdaterError::BadState => Error::BadState,
            // Only embassy-boot's own ed25519 verify returns it, and those features
            // remove `mark_updated`, so this adapter never sees it.
            FirmwareUpdaterError::Signature(_) => Error::Flash(NorFlashErrorKind::Other),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rejected(e) => write!(f, "update rejected: {e}"),
            Error::NotAccepted => f.write_str("update verified but not accepted by the caller"),
            Error::KeySet(e) => write!(f, "trusted key set is invalid: {e}"),
            Error::Config(e) => write!(f, "updater configuration is invalid: {e}"),
            Error::BadState => f.write_str("an update is already pending (state is Swap)"),
            Error::Flash(kind) => write!(f, "state partition flash error: {kind:?}"),
        }
    }
}

impl core::error::Error for Error {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigError::AlignedBufferLen => "the aligned state buffer has the wrong length",
            ConfigError::DfuUnaligned => "the DFU partition is not aligned to the flash",
            ConfigError::StateUnaligned => "the state partition is not aligned to the flash",
            ConfigError::PartitionsOverlap => "the DFU and state partitions overlap",
            ConfigError::DfuSlotEmpty => "the DFU partition is empty",
            ConfigError::PartitionOutOfRange => "a partition ends past the 32-bit flash offsets",
        })
    }
}

impl core::error::Error for ConfigError {}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}", defmt::Debug2Format(self));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ConfigError {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}", defmt::Debug2Format(self));
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

    use std::collections::BTreeSet;
    use std::format;
    use std::string::ToString;
    use std::vec::Vec;

    use keelsign_verify::{Algorithm, Ed25519Error, ImageError, ReadError};

    use super::*;

    /// One value of every variant. The match is exhaustive, so a new variant needs a
    /// value here.
    fn every_variant() -> Vec<Error> {
        let all = Vec::from([
            Error::Rejected(keelsign_verify::Error::SignatureInvalid),
            Error::Rejected(keelsign_verify::Error::KeyNotTrusted),
            Error::Rejected(keelsign_verify::Error::Image(ImageError::DigestMismatch)),
            Error::Rejected(keelsign_verify::Error::Ed25519(
                Ed25519Error::SignatureInvalid,
            )),
            Error::Rejected(keelsign_verify::Error::Read(ReadError::OutOfBounds)),
            Error::NotAccepted,
            Error::KeySet(KeySetError::InvalidPublicKeyLength(Algorithm::LmsHss)),
            Error::Config(ConfigError::AlignedBufferLen),
            Error::Config(ConfigError::DfuUnaligned),
            Error::Config(ConfigError::StateUnaligned),
            Error::Config(ConfigError::PartitionsOverlap),
            Error::Config(ConfigError::DfuSlotEmpty),
            Error::Config(ConfigError::PartitionOutOfRange),
            Error::BadState,
            Error::Flash(NorFlashErrorKind::Other),
            Error::Flash(NorFlashErrorKind::OutOfBounds),
        ]);
        for e in &all {
            match e {
                Error::Rejected(_)
                | Error::NotAccepted
                | Error::KeySet(_)
                | Error::Config(_)
                | Error::BadState
                | Error::Flash(_) => {}
            }
            if let Error::Config(c) = e {
                match c {
                    ConfigError::AlignedBufferLen
                    | ConfigError::DfuUnaligned
                    | ConfigError::StateUnaligned
                    | ConfigError::PartitionsOverlap
                    | ConfigError::DfuSlotEmpty
                    | ConfigError::PartitionOutOfRange => {}
                }
            }
        }
        all
    }

    #[test]
    fn every_error_variant_debug_and_display_are_distinct_and_name_the_verify_variant() {
        let all = every_variant();
        let displays: BTreeSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(displays.len(), all.len(), "Display strings are distinct");
        let debugs: BTreeSet<_> = all.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(debugs.len(), all.len(), "Debug strings are distinct");
        for e in &all {
            if let Error::Rejected(inner) = e {
                // The reject names keelsign-verify's variant, in both forms (AC2: the
                // defmt log uses Debug).
                assert!(
                    e.to_string()
                        .starts_with(&format!("update rejected: {inner}")),
                    "{e}"
                );
                assert!(format!("{e:?}").contains(&format!("{inner:?}")), "{e:?}");
            } else {
                assert!(!e.to_string().starts_with("update rejected"), "{e}");
            }
        }
        assert_eq!(
            Error::from(keelsign_verify::Error::SignatureInvalid),
            Error::Rejected(keelsign_verify::Error::SignatureInvalid)
        );
        assert_eq!(
            Error::from(ConfigError::DfuSlotEmpty),
            Error::Config(ConfigError::DfuSlotEmpty)
        );
    }

    #[test]
    fn firmware_updater_errors_map() {
        for kind in [
            NorFlashErrorKind::NotAligned,
            NorFlashErrorKind::OutOfBounds,
            NorFlashErrorKind::Other,
        ] {
            assert_eq!(
                Error::from(FirmwareUpdaterError::Flash(kind)),
                Error::Flash(kind)
            );
        }
        assert_eq!(Error::from(FirmwareUpdaterError::BadState), Error::BadState);
    }
}
