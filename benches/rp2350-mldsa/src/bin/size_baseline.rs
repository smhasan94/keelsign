//! Flash-footprint baseline for the Pico 2 W / RP2350: HAL init, one defmt line, and a
//! black-boxed reference to both on-target fixtures, so that the fixture bytes cancel
//! out of the `size_mldsa44` / `size_mldsa65` deltas (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use mldsa_kat::{MLDSA44_TARGET, MLDSA65_TARGET};

#[entry]
fn main() -> ! {
    let _p = embassy_rp::init(Default::default());
    let [a, b] = black_box([MLDSA44_TARGET, MLDSA65_TARGET]);
    info!("size_baseline fixtures={=usize}+{=usize}", a.len(), b.len());
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
