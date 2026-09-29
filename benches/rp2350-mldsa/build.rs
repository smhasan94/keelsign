//! Copies `memory.x` to `OUT_DIR`, puts it on the linker search path and passes the
//! cortex-m-rt, defmt and embedded-test linker scripts.
//!
//! Unlike the examples this uses `cargo:rustc-link-arg=` (not `-bins`): the on-target
//! tests under `tests/` are linked with the same scripts, and embedded-test needs
//! `embedded-test.x` to keep its test-case section.

// Host-side build script, not no_std firmware: failing the build with a message is the
// right response to a missing OUT_DIR or an unwritable memory.x.
#![allow(clippy::expect_used)]

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).expect("write memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rustc-link-arg=-Tdefmt.x");
    println!("cargo:rustc-link-arg=-Tembedded-test.x");
    // The `#[embedded_test::tests]` expansion checks `cfg(rust_analyzer)` (upstream README).
    println!("cargo:rustc-check-cfg=cfg(rust_analyzer)");
}
