//! Stack painting for the SHA-34 on-target benchmarks: fill the unused stack with a
//! pattern, run the code under test, then find the lowest word it overwrote.
//!
//! Measurement only. This crate holds the only `unsafe` outside `keelsign-ffi`
//! (CLAUDE.md): the `arm` module, compiled only for Arm targets. It must never be a
//! dependency of a shipped crate.
//!
//! The stack layout assumed is flip-link's: the stack grows down from just below
//! `.data`/`.bss` towards `_stack_end`, which flip-link sets to `ORIGIN(RAM)`.
#![no_std]
#![deny(unsafe_code)]

/// The word painted into unused stack.
pub const PATTERN: u32 = 0x5AC3_A53C;

/// The deepest stack use seen by `high_water`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermark {
    /// Bytes between the reference stack pointer and the lowest overwritten word.
    pub bytes: u32,
    /// True when even the bottom word of the stack was overwritten, so `bytes` is only
    /// a lower bound (the stack may have run out).
    pub saturated: bool,
}

#[cfg(target_arch = "arm")]
pub use arm::{high_water, paint};

#[cfg(target_arch = "arm")]
#[allow(unsafe_code)]
pub mod arm {
    use super::{PATTERN, Watermark};
    use core::ptr;

    unsafe extern "C" {
        /// Lowest address of the stack region, from cortex-m-rt / flip-link.
        static _stack_end: u32;
    }

    fn stack_bottom() -> usize {
        // Taking the address of an extern static is safe; the symbol is never read.
        ptr::addr_of!(_stack_end) as usize
    }

    /// Paints [`PATTERN`] over the stack from `_stack_end` up to `margin` bytes below the
    /// current main stack pointer. `margin` must cover this function's own frame.
    ///
    /// Preconditions (not checked):
    /// - the caller runs in thread mode on the main stack (MSP);
    /// - the memory layout is flip-link's, with `_stack_end` = `ORIGIN(RAM)` and the stack
    ///   growing down towards it;
    /// - nothing else owns RAM below the stack pointer (no heap or other data there);
    /// - no interrupt handler depends on memory below the stack pointer.
    pub fn paint(margin: u32) {
        let top = cortex_m::register::msp::read().saturating_sub(margin) as usize;
        let mut addr = stack_bottom();
        while addr.saturating_add(4) <= top {
            // SAFETY: `addr` is word-aligned (cortex-m-rt aligns `_stack_end` to 4) and lies
            // in `[_stack_end, msp - margin)`: RAM reserved for the stack and below every
            // live frame, so nothing else reads or owns it.
            unsafe { ptr::write_volatile(addr as *mut u32, PATTERN) };
            addr += 4;
        }
    }

    /// Scans up from `_stack_end` for the first word that no longer holds [`PATTERN`] and
    /// returns its distance below `sp0` (the stack pointer read before [`paint`]).
    ///
    /// Preconditions (not checked):
    /// - the caller runs in thread mode on the main stack (MSP);
    /// - the memory layout is flip-link's, with `_stack_end` = `ORIGIN(RAM)` and the stack
    ///   growing down towards it;
    /// - nothing else owns RAM below the stack pointer (no heap or other data there);
    /// - no interrupt handler depends on memory below the stack pointer.
    pub fn high_water(sp0: u32) -> Watermark {
        let bottom = stack_bottom();
        let sp0 = sp0 as usize;
        let mut addr = bottom;
        // SAFETY: `addr` stays word-aligned in `[_stack_end, sp0)`, stack RAM below the
        // caller's frame; a volatile read of it has no side effects.
        while addr < sp0 && unsafe { ptr::read_volatile(addr as *const u32) } == PATTERN {
            addr += 4;
        }
        Watermark {
            bytes: u32::try_from(sp0.saturating_sub(addr)).unwrap_or(u32::MAX),
            saturated: addr == bottom,
        }
    }
}
