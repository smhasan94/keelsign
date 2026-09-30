//! Flash-footprint baseline for LMS/HSS on the Pico 2 W / RP2350: HAL init, one defmt line, a
//! black-boxed reference to the on-target LMS fixture, a parse of it that finds its first
//! case accepted by the keelsign policy, and a trusted-key set holding that case's key
//! (which computes its key ID with SHA-256). The fixture bytes, the parser, SHA-256 and
//! the key set therefore cancel out of the `size_lms` delta, which leaves `verify_pq`
//! with the LMS/HSS backend (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use lms_kat::{Expect, Fixture, LMS_TARGET, trusted_lms_key};

#[entry]
fn main() -> ! {
    let _p = embassy_rp::init(Default::default());
    let fixture = black_box(LMS_TARGET);
    info!("size_lms_baseline fixture={=usize}", fixture.len());
    let case = Fixture::parse(fixture)
        .ok()
        .and_then(|f| f.cases().flatten().find(|c| c.expect_default == Expect::Ok));
    let keys = case.and_then(|c| trusted_lms_key(black_box(c.pk)).ok());
    let keys = black_box(keys);
    info!(
        "size_lms_baseline tc={=u16} keys={=usize}",
        case.map_or(0, |c| c.id),
        keys.map_or(0, |k| k.len())
    );
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
