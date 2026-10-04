//! embassy-boot application for the Raspberry Pi Pico 2 W (RP2350) with keelsign
//! verification through the async updater (SHA-55).
//!
//! On every boot it logs `hello from keelsign boot app A` (or `B` with the `b` feature)
//! and reads the bootloader state:
//!
//! - `Swap`: the bootloader just swapped this image in; confirm it (`mark_booted`).
//! - `Revert`: the last update did not confirm and was reverted; confirm the running
//!   image and erase the DFU image's header so the failed update is not tried again.
//! - otherwise: verify the DFU slot with keelsign-embassy (LMS/HSS, `PqOnly`, the key of
//!   `tests/fixtures/images/keelsign-lms-m32-h5.bin`) and, if it is valid and newer than
//!   this application, mark it for swap and reset. A rejected image is logged with the
//!   reason and nothing is written.
//!
//! The application takes over the bootloader's watchdog (embassy-boot-rp's
//! `WatchdogFlash`) and feeds it once a second while it runs, so only an image that never
//! runs (or hangs) is reset and reverted. The `soak` feature verifies in a loop and never
//! marks (docs/embassy.md P4). Flash the bootloader and the signed image as
//! docs/embassy.md describes.
#![no_std]
#![no_main]

use defmt::{error, info};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaInterruptHandler;
use embassy_rp::flash::Flash;
use embassy_rp::peripherals::DMA_CH0;
use embassy_rp::watchdog::Watchdog;
use embassy_time::{Duration, Timer};
use keelsign_embassy::{
    Algorithm, AlignedBuffer, Config, DEFAULT_CHUNK_LEN, Policy, State, TrustedKey, VerifiedImage,
    rp,
};
use {defmt_rtt as _, panic_probe as _};

/// Which build this is.
const APP: &str = if cfg!(feature = "b") { "B" } else { "A" };

/// The version this application is signed with (docs/embassy.md): only a newer image in
/// the DFU slot is marked, so the previous application, which the swap leaves in the DFU
/// slot, is never swapped back in.
const RUNNING_VERSION: (u8, u8, u16) = if cfg!(feature = "b") {
    (2, 0, 0)
} else {
    (1, 0, 0)
};

/// The LMS/HSS public key (HSS `L || LMS key`, 60 bytes) of
/// `tests/fixtures/images/keelsign-lms-m32-h5.bin`, from MANIFEST.json `public_key_hex`
/// (repo-checks `boot_app_trusted_key_matches_fixture_manifest` keeps them equal).
static TRUSTED_KEY: [u8; 60] = [
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x7b, 0x68, 0x45, 0x09,
    0x2e, 0x59, 0x6e, 0x39, 0x5f, 0x31, 0xa2, 0x36, 0x80, 0x32, 0x49, 0xbb, 0x11, 0xb6, 0x3a, 0x11,
    0xdb, 0x62, 0x6b, 0x6c, 0xd7, 0xf9, 0x45, 0x41, 0x29, 0xf2, 0x7a, 0xb7, 0xa8, 0x7f, 0x2b, 0x98,
    0x7c, 0x77, 0xa5, 0x1f, 0x7e, 0xe3, 0x6f, 0xdb, 0x1c, 0x58, 0xcc, 0x0a,
];

/// The device's keelsign configuration: post-quantum only, one trusted LMS/HSS key.
const CONFIG: Config<'static, 1> = Config::new(
    Policy::PqOnly,
    [TrustedKey {
        algorithm: Algorithm::LmsHss,
        public_key: &TRUSTED_KEY,
    }],
    [],
);

/// Accepts only an image newer than the running application.
#[cfg_attr(feature = "soak", allow(dead_code))]
fn newer_than_running(image: &VerifiedImage<'_>) -> bool {
    let v = image.version;
    (v.major, v.minor, v.revision) > RUNNING_VERSION
}

/// The flash size given to embassy-rp's driver: the Pico 2 W has 4 MiB, the layout uses
/// the first 2 MiB (as examples/rp2350-hello's memory.x does).
const FLASH_SIZE: usize = 2 * 1024 * 1024;

/// The watchdog timeout (the upstream embassy-boot-rp bootloader example's).
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(8);

bind_interrupts!(struct Irqs {
    DMA_IRQ_0 => DmaInterruptHandler<DMA_CH0>;
});

/// The async updater of this application.
type Updater<'a, 'd> = rp::Async<'a, 'd, 'static, FLASH_SIZE, 1, 0>;

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("hello from keelsign boot app {} (Pico 2 W / RP2350)", APP);

    // Take over the bootloader's watchdog (as the upstream embassy-boot-rp example does).
    let mut dog = Watchdog::new(p.WATCHDOG);
    dog.start(WATCHDOG_TIMEOUT);

    let flash = rp::SharedAsyncFlash::new(Flash::new(p.FLASH, p.DMA_CH0, Irqs));
    let mut aligned = AlignedBuffer([0u8; rp::ASYNC_STATE_BUF_LEN]);
    match rp::async_from_linkerfile(&flash, &mut aligned.0, &CONFIG) {
        Ok(mut updater) => update(&mut updater, &mut dog).await,
        Err(e) => error!("keelsign-embassy updater: {}", e),
    }

    let mut n: u32 = 0;
    loop {
        Timer::after_secs(1).await;
        n = n.wrapping_add(1);
        dog.feed(WATCHDOG_TIMEOUT);
        info!("app {} tick {}", APP, n);
    }
}

async fn update(updater: &mut Updater<'_, '_>, dog: &mut Watchdog) {
    match updater.get_state().await {
        Ok(State::Swap) => match updater.mark_booted().await {
            Ok(()) => info!("state Swap: app {} confirmed (mark_booted)", APP),
            Err(e) => error!("mark_booted: {}", e),
        },
        Ok(State::Revert) => {
            match updater.mark_booted().await {
                Ok(()) => info!(
                    "state Revert: the update was reverted; app {} confirmed",
                    APP
                ),
                Err(e) => error!("mark_booted: {}", e),
            }
            // Drop the failed update so it is not tried again: rewriting the first bytes
            // erases the DFU slot's first page, header included (a whole-slot erase would
            // outlast the watchdog).
            match updater.write_firmware(0, &[0xFF; 4]).await {
                Ok(()) => info!("DFU image header erased"),
                Err(e) => error!("erase DFU header: {}", e),
            }
        }
        Ok(state) => {
            info!("state {}: verifying the DFU slot", state);
            verify_dfu(updater, dog).await;
        }
        Err(e) => error!("get_state: {}", e),
    }
}

#[cfg(not(feature = "soak"))]
async fn verify_dfu(updater: &mut Updater<'_, '_>, dog: &mut Watchdog) {
    dog.feed(WATCHDOG_TIMEOUT);
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    match updater
        .verify_and_mark_updated_if(&mut tlv_buf, &mut chunk, newer_than_running)
        .await
    {
        Ok(image) => {
            let v = image.version;
            info!(
                "update {}.{}.{}+{} verified and marked for swap; resetting",
                v.major, v.minor, v.revision, v.build_num
            );
            Timer::after_millis(100).await;
            cortex_m::peripheral::SCB::sys_reset();
        }
        Err(e) => error!("no update: {}", e),
    }
}

#[cfg(feature = "soak")]
async fn verify_dfu(updater: &mut Updater<'_, '_>, dog: &mut Watchdog) {
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    let mut n: u32 = 0;
    loop {
        n = n.wrapping_add(1);
        dog.feed(WATCHDOG_TIMEOUT);
        info!("soak: verify {} start", n);
        match updater.verify(&mut tlv_buf, &mut chunk).await {
            Ok(_) => info!("soak: verify {} ok (not marked)", n),
            Err(e) => error!("soak: verify {}: {}", n, e),
        }
        Timer::after_millis(10).await;
    }
}
