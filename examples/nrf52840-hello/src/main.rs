//! Hello world for the nRF52840-DK: logs `hello from keelsign` over defmt/RTT, then a
//! tick every second while toggling LED1 (P0.13, active-low).
//!
//! Run with `cargo run` from this directory (see docs/setup.md).
#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());
    // LED1 is active-low: start High, i.e. off.
    let mut led = Output::new(p.P0_13, Level::High, OutputDrive::Standard);

    info!("hello from keelsign (nRF52840-DK)");

    let mut n: u32 = 0;
    loop {
        Timer::after_secs(1).await;
        n = n.wrapping_add(1);
        info!("tick {}", n);
        led.toggle();
    }
}
