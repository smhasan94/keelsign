//! Hello world for the Raspberry Pi Pico 2 W (RP2350): logs `hello from keelsign` over
//! defmt/RTT, then a tick every second. The Pico 2 W's LED sits behind the CYW43 radio,
//! so this example does not blink it.
//!
//! Run with `cargo run` from this directory (see docs/setup.md).
#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    let _p = embassy_rp::init(Default::default());

    info!("hello from keelsign (Pico 2 W / RP2350)");

    let mut n: u32 = 0;
    loop {
        Timer::after_secs(1).await;
        n = n.wrapping_add(1);
        info!("tick {}", n);
    }
}
