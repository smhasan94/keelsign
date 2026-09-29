//! Flash footprint of ML-DSA-65 verify on the nRF52840-DK: `size_baseline` plus one
//! black-boxed verify of the first valid case of the embedded ML-DSA-65 fixture
//! (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use mldsa_kat::{Fixture, MLDSA44_TARGET, MLDSA65_TARGET, MlDsa65, verify_case};

#[entry]
fn main() -> ! {
    let _p = embassy_nrf::init(Default::default());
    let [a, b] = black_box([MLDSA44_TARGET, MLDSA65_TARGET]);
    info!("size_mldsa65 fixtures={=usize}+{=usize}", a.len(), b.len());
    let case = Fixture::parse(b)
        .ok()
        .and_then(|f| f.cases().flatten().find(|c| c.expect_valid));
    let verified = case.is_some_and(|c| verify_case::<MlDsa65>(black_box(&c)));
    info!("size_mldsa65 verified={=bool}", verified);
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
