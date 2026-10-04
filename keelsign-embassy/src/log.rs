//! defmt logging of the verify-and-mark outcome (the `defmt` feature; no-ops without it).

use keelsign_verify::VerifiedImage;

use crate::error::Error;

/// Logs a verify-and-mark result: `info` when the image was marked for swap, `error`
/// with the reason (keelsign-verify's variant for a rejected image) otherwise.
pub(crate) fn outcome(result: &Result<VerifiedImage<'_>, Error>) {
    #[cfg(feature = "defmt")]
    match result {
        Ok(image) => defmt::info!(
            "keelsign-embassy: update verified ({}) and marked for swap",
            defmt::Debug2Format(&image.version)
        ),
        Err(e) => defmt::error!("keelsign-embassy: update rejected: {}", e),
    }
    #[cfg(not(feature = "defmt"))]
    let _ = result;
}
