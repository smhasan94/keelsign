//! Flash footprint of LMS/HSS verify on the Pico 2 W / RP2350: `size_lms_baseline` plus one
//! black-boxed `verify_pq` (key-ID and signature TLV selection, dispatch and the LMS/HSS
//! backend) of the first case of the on-target LMS fixture accepted by the keelsign
//! policy (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use lms_kat::{Expect, Fixture, LMS_TARGET, trusted_lms_key, verify_with_keys};

#[entry]
fn main() -> ! {
    let _p = embassy_rp::init(Default::default());
    let fixture = black_box(LMS_TARGET);
    info!("size_lms fixture={=usize}", fixture.len());
    let case = Fixture::parse(fixture)
        .ok()
        .and_then(|f| f.cases().flatten().find(|c| c.expect_cnsa == Expect::Ok));
    let keys = case.and_then(|c| trusted_lms_key(black_box(c.pk)).ok());
    let keys = black_box(keys);
    let verified = match (keys, case) {
        (Some(keys), Some(case)) => verify_with_keys(&keys, black_box(&case)).is_ok(),
        _ => false,
    };
    info!(
        "size_lms tc={=u16} verified={=bool}",
        case.map_or(0, |c| c.id),
        verified
    );
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
