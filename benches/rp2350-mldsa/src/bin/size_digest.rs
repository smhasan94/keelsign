//! Flash footprint of the image digest on the Pico 2 W / RP2350 (SHA-42): `size_digest_baseline`
//! plus a black-boxed `Image::read_from` and `image_digest` (256-byte chunk) of the small
//! golden image `mcuboot-ed25519.bin` (each in its own `#[inline(never)]` wrapper, so that
//! the static frames can be read per step) through `NorFlashReader` over the blocking flash driver
//! (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use keelsign_verify::image::Image;
use keelsign_verify::{DEFAULT_CHUNK_LEN, ImageReader, NorFlashReader, image_digest};

/// External QSPI flash of the Pico 2 W: 4 MiB.
const FLASH_SIZE: usize = 4 * 1024 * 1024;
/// Where the XIP window maps the flash.
const XIP_BASE: u32 = 0x1000_0000;

static IMAGE: &[u8] = include_bytes!("../../../../tests/fixtures/images/mcuboot-ed25519.bin");

/// `Image::read_from` on its own frame, for the static-frame figure (docs/benchmarks.md).
#[inline(never)]
fn read_image<'a, R: ImageReader>(reader: &mut R, tlv_buf: &'a mut [u8]) -> Option<Image<'a>> {
    Image::read_from(reader, tlv_buf).ok()
}

/// `image_digest` on its own frame, for the static-frame figure (docs/benchmarks.md).
#[inline(never)]
fn digest<R: ImageReader>(reader: &mut R, image: &Image<'_>, chunk: &mut [u8]) -> Option<[u8; 32]> {
    image_digest(reader, image, chunk).ok()
}

#[entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    let flash = black_box(Flash::<'_, FLASH, Blocking, FLASH_SIZE>::new_blocking(
        p.FLASH,
    ));
    let image = black_box(IMAGE);
    info!(
        "size_digest image={=usize} at={=u32}",
        image.len(),
        image.as_ptr() as u32
    );
    let len = u32::try_from(image.len()).unwrap_or(0);
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    let first = (image.as_ptr() as u32)
        .checked_sub(XIP_BASE)
        .and_then(|base| NorFlashReader::new(flash, base, len).ok())
        .and_then(|mut reader| {
            let parsed = read_image(&mut reader, black_box(&mut tlv_buf))?;
            digest(&mut reader, &parsed, black_box(&mut chunk))
        })
        .map_or(0, |digest| digest[0]);
    info!("size_digest digest[0]={=u8}", black_box(first));
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
