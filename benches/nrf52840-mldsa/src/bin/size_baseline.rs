//! Flash-footprint baseline for the nRF52840-DK: HAL init, one defmt line, and a
//! black-boxed reference to both on-target fixtures, and a parse of the ML-DSA-44 fixture
//! that finds and logs its first valid case without verifying it. The fixture bytes and
//! the parser therefore cancel out of the `size_mldsa44` / `size_mldsa65` deltas, which
//! leaves verify itself (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use mldsa_kat::{Fixture, MLDSA44_TARGET, MLDSA65_TARGET};

#[entry]
fn main() -> ! {
    let _p = embassy_nrf::init(Default::default());
    let [a, b] = black_box([MLDSA44_TARGET, MLDSA65_TARGET]);
    info!("size_baseline fixtures={=usize}+{=usize}", a.len(), b.len());
    let case = Fixture::parse(a)
        .ok()
        .and_then(|f| f.cases().flatten().find(|c| c.expect_valid));
    let tc_id = black_box(case).map_or(0, |c| c.tc_id);
    info!("size_baseline first_valid_tc={=u32}", tc_id);
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
