//! Cycle measurement with the Cortex-M DWT cycle counter (`CYCCNT`).
//!
//! The caller enables the counter once (`DCB::enable_trace` then
//! `DWT::enable_cycle_counter`) before using [`Cycles`].

use cortex_m::peripheral::DWT;

/// A running cycle measurement started at a `CYCCNT` value.
#[derive(Clone, Copy, Debug)]
pub struct Cycles {
    start: u32,
}

impl Cycles {
    /// Starts a measurement at the current `CYCCNT`.
    #[inline(always)]
    pub fn start() -> Self {
        Self {
            start: DWT::cycle_count(),
        }
    }

    /// Cycles since [`Cycles::start`]. `CYCCNT` is 32 bits and wraps, so this is exact
    /// for intervals shorter than 2^32 cycles (about 67 s at 64 MHz, 28 s at 150 MHz).
    #[inline(always)]
    pub fn elapsed(&self) -> u32 {
        DWT::cycle_count().wrapping_sub(self.start)
    }
}
