//! The C ABI: the only module of this crate where `unsafe` is allowed. Every `unsafe`
//! block carries a `// SAFETY:` comment.

/// Panics cannot unwind across the C ABI and must not reach formatting code: trap.
/// The `PanicInfo` is never read, so no message is formatted.
#[cfg(all(not(test), not(panic = "unwind"), target_os = "none"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        // SAFETY: `udf` raises an undefined-instruction exception (HardFault on
        // Cortex-M); it touches no memory and no stack.
        unsafe { core::arch::asm!("udf #0", options(nomem, nostack)) };
    }
}

/// On a hosted target (the C harness, host tools) a panic aborts the process.
#[cfg(all(not(test), not(panic = "unwind"), not(target_os = "none")))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe extern "C" {
        safe fn abort() -> !;
    }
    abort()
}
