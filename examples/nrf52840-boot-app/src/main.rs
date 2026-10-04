//! embassy-boot application for the nRF52840-DK with keelsign verification (SHA-55).
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
//! The bootloader's watchdog (embassy-boot-nrf's `WatchdogFlash`) is petted once a
//! second while the application runs, so only an image that never runs (or hangs) is
//! reset and reverted. The `soak` feature verifies in a loop and never marks
//! (docs/embassy.md P4). Flash the bootloader and the signed image as docs/embassy.md
//! describes.
#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt::{error, info};
use embassy_executor::Spawner;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::wdt::{self, Watchdog, WatchdogHandle};
use embassy_time::Timer;
use keelsign_embassy::{
    Algorithm, AlignedBuffer, Config, DEFAULT_CHUNK_LEN, Policy, State, TrustedKey, VerifiedImage,
    nrf,
};
use {defmt_rtt as _, panic_probe as _};

/// Which build this is.
const APP: &str = if cfg!(feature = "b") { "B" } else { "A" };

/// The version this application is signed with (docs/embassy.md). `newer_than_running`
/// demonstrates the anti-rollback `accept` hook: an older image that is validly signed
/// (written to the DFU slot by mistake or by an attacker) is verified, then refused with
/// `NotAccepted` and not marked.
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

/// Accepts only an image newer than the running application, comparing
/// `(major, minor, revision)`: `build_num` is ignored (MCUboot's default comparison).
#[cfg_attr(feature = "soak", allow(dead_code))]
fn newer_than_running(image: &VerifiedImage<'_>) -> bool {
    let v = image.version;
    (v.major, v.minor, v.revision) > RUNNING_VERSION
}

/// The watchdog the bootloader started, if any.
struct Dog(Option<WatchdogHandle>);

impl Dog {
    fn pet(&mut self) {
        if let Some(handle) = &mut self.0 {
            handle.pet();
        }
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());
    info!("hello from keelsign boot app {} (nRF52840-DK)", APP);

    // Take over the watchdog the bootloader started, with its configuration.
    let mut dog = match wdt::Config::try_new(&p.WDT) {
        Some(config) => match Watchdog::try_new(p.WDT, config) {
            Ok((_wdt, [handle])) => Dog(Some(handle)),
            Err(_) => {
                error!("the running watchdog has other handles; it will reset the device");
                Dog(None)
            }
        },
        None => Dog(None),
    };

    let flash = nrf::SharedNvmc::new(RefCell::new(Nvmc::new(p.NVMC)));
    let mut aligned = AlignedBuffer([0u8; nrf::BLOCKING_STATE_BUF_LEN]);
    match nrf::blocking_from_linkerfile(&flash, &mut aligned.0, &CONFIG) {
        Ok(mut updater) => update(&mut updater, &mut dog).await,
        Err(e) => error!("keelsign-embassy updater: {}", e),
    }

    let mut n: u32 = 0;
    loop {
        Timer::after_secs(1).await;
        n = n.wrapping_add(1);
        dog.pet();
        info!("app {} tick {}", APP, n);
    }
}

async fn update(updater: &mut nrf::Blocking<'_, '_, 'static, 1, 0>, dog: &mut Dog) {
    match updater.get_state() {
        Ok(State::Swap) => match updater.mark_booted() {
            Ok(()) => info!("state Swap: app {} confirmed (mark_booted)", APP),
            Err(e) => error!("mark_booted: {}", e),
        },
        Ok(State::Revert) => {
            match updater.mark_booted() {
                Ok(()) => info!(
                    "state Revert: the update was reverted; app {} confirmed",
                    APP
                ),
                Err(e) => error!("mark_booted: {}", e),
            }
            // Drop the failed update so it is not tried again: rewriting the first bytes
            // erases the DFU slot's first page, header included (a whole-slot erase would
            // outlast the watchdog).
            match updater.write_firmware(0, &[0xFF; 4]) {
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
async fn verify_dfu(updater: &mut nrf::Blocking<'_, '_, 'static, 1, 0>, dog: &mut Dog) {
    dog.pet();
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    match updater.verify_and_mark_updated_if(&mut tlv_buf, &mut chunk, newer_than_running) {
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
async fn verify_dfu(updater: &mut nrf::Blocking<'_, '_, 'static, 1, 0>, dog: &mut Dog) {
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    let mut n: u32 = 0;
    loop {
        n = n.wrapping_add(1);
        dog.pet();
        info!("soak: verify {} start", n);
        match updater.verify(&mut tlv_buf, &mut chunk) {
            Ok(_) => info!("soak: verify {} ok (not marked)", n),
            Err(e) => error!("soak: verify {}: {}", n, e),
        }
        Timer::after_millis(10).await;
    }
}
