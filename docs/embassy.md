# embassy-boot with keelsign (SHA-55)

`keelsign-embassy` lets an [embassy-boot](https://docs.embassy.dev/embassy-boot)
application verify the image in its DFU slot with `keelsign-verify` before it marks the
image for swap. The image format is MCUboot's (docs/image-format.md), so the same
signed image works with MCUboot and embassy-boot. This page has the partition layout of
both boards, the bootloader, how to build and flash the example applications, and the
on-target procedures P1 to P4. The procedures need the boards (NEEDS-HARDWARE): a human
runs them and records the RTT log and the state word.

The flow on the device:

1. The application receives an update into the DFU slot (`write_firmware`, or a debug
   probe in the procedures below).
2. It calls `verify_and_mark_updated` (or `_if`, with an anti-rollback check). The
   adapter refuses a pending swap (`BadState`), reads the DFU slot only, verifies the
   image under the device's policy and trusted keys, and only if the image is accepted
   writes the swap magic to the state page (`mark_updated`).
3. On the next reset the bootloader swaps the DFU image into the active slot and jumps
   to it. The new application confirms itself with `mark_booted`; if it never does (it
   faults, hangs or resets first), the bootloader swaps the old image back (`Revert`).

A rejected image writes nothing: the state page keeps `Boot` and the current
application keeps booting. The error names the reason (`Rejected(<keelsign-verify
error>)`), and with the `defmt` feature the adapter logs it.

The crate's API is in `keelsign-embassy/README.md`; the example applications are
`examples/nrf52840-boot-app` (blocking updater) and `examples/rp2350-boot-app` (async
updater).

## Partition layout

embassy-boot needs a state page and a DFU slot one page (4 KiB) larger than the active
slot. keelsign images keep MCUboot's 0x200-byte header, so the application is linked at
ACTIVE + 0x200 (its `memory.x` `FLASH` region) and the bootloader jumps to
ACTIVE + 0x200.

nRF52840-DK (`nRF52840_xxAA`, flash at 0x00000000):

| Region | Start | Size | Notes |
|---|---|---|---|
| Bootloader | 0x00000000 | 24 KiB | the bootloader below |
| State | 0x00006000 | 4 KiB | first word: the state magic |
| Active | 0x00007000 | 256 KiB | MCUboot header at 0x00007000, application at 0x00007200 |
| DFU | 0x00047000 | 260 KiB | the update image, header first |

Raspberry Pi Pico 2 W (`RP235x`, flash at 0x10000000, the first 2 MiB used):

| Region | Start | Size | Notes |
|---|---|---|---|
| Bootloader | 0x10000000 | 24 KiB | the bootloader below (with the RP2350 IMAGE_DEF) |
| State | 0x10006000 | 4 KiB | first word: the state magic |
| Active | 0x10007000 | 512 KiB | MCUboot header at 0x10007000, application at 0x10007200 |
| DFU | 0x10087000 | 516 KiB | the update image, header first |

The applications' `memory.x` define `__bootloader_state_*` and `__bootloader_dfu_*` as
offsets from the start of flash, which embassy-boot's `from_linkerfile` reads.

### Reading the state word

```sh
probe-rs read --chip nRF52840_xxAA b8 0x6000 4    # nRF52840-DK
probe-rs read --chip RP235x b8 0x10006000 4       # Pico 2 W
```

| Bytes | State |
|---|---|
| `ff ff ff ff` (erased) or `d0 d0 d0 d0` | `Boot` |
| `f0 f0 f0 f0` | `Swap`: an update is marked (or swapped in and not confirmed yet) |
| `c0 c0 c0 c0` | `Revert`: the bootloader swapped the old image back |
| `e0 e0 e0 e0` | `DfuDetach` |

## Bootloader

The bootloader is not in this repository: it needs `unsafe` (jumping to the
application), which CLAUDE.md allows only in `keelsign-ffi`. Build it out of tree from
the listings below: the nRF one is the upstream embassy example (tag
`embassy-boot-nrf-v0.12.0`, `examples/boot/bootloader/nrf`) with one change, and the
RP2350 one ports the upstream RP2040 example (tag `embassy-boot-rp-v0.10.0`,
`examples/boot/bootloader/rp`; upstream has no RP235x bootloader) with the same change.
The change: `bl.load(active_offset)` becomes `bl.load(active_offset + 0x200)` (RP2350:
`bl.load(FLASH_BASE + active_offset + 0x200)`) so it jumps past the MCUboot header. Both
start the watchdog (`WatchdogFlash`: 5 s on nRF, 8 s on RP2350), which the example
applications pet; an image that never runs is reset and reverted.

Both listings were built with Rust 1.91.1 (`cargo build --release`) for SHA-55.

### nRF52840 bootloader

Create a directory outside the repository with these files.

`Cargo.toml`:

```toml
[package]
name = "nrf52840-bootloader"
version = "0.0.0"
edition = "2024"
license = "MIT OR Apache-2.0"
publish = false

[workspace]

[dependencies]
embassy-boot-nrf = "=0.12.0"
embassy-nrf = { version = "=0.11.0", features = ["nrf52840"] }
embassy-sync = "=0.8.0"
cortex-m = { version = "=0.7.9", features = ["inline-asm", "critical-section-single-core"] }
cortex-m-rt = "=0.7.7"

[profile.release]
codegen-units = 1
debug = 2
lto = "fat"
opt-level = "z"
```

`.cargo/config.toml`:

```toml
[build]
target = "thumbv7em-none-eabihf"
```

`memory.x`:

```text
MEMORY
{
  FLASH            : ORIGIN = 0x00000000, LENGTH = 24K
  BOOTLOADER_STATE : ORIGIN = 0x00006000, LENGTH = 4K
  ACTIVE           : ORIGIN = 0x00007000, LENGTH = 256K
  DFU              : ORIGIN = 0x00047000, LENGTH = 260K
  RAM        (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

__bootloader_state_start = ORIGIN(BOOTLOADER_STATE);
__bootloader_state_end = ORIGIN(BOOTLOADER_STATE) + LENGTH(BOOTLOADER_STATE);

__bootloader_active_start = ORIGIN(ACTIVE);
__bootloader_active_end = ORIGIN(ACTIVE) + LENGTH(ACTIVE);

__bootloader_dfu_start = ORIGIN(DFU);
__bootloader_dfu_end = ORIGIN(DFU) + LENGTH(DFU);
```

`build.rs`:

```rust
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
}
```

`src/main.rs`:

```rust
//! The upstream embassy nRF bootloader example (embassy-boot-nrf-v0.12.0,
//! examples/boot/bootloader/nrf), with one change: it jumps past the 0x200-byte MCUboot
//! header of keelsign images.
#![no_std]
#![no_main]

use core::cell::RefCell;

use cortex_m_rt::{entry, exception};
use embassy_boot_nrf::*;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::wdt::{self, HaltConfig, SleepConfig};
use embassy_sync::blocking_mutex::Mutex;

/// The MCUboot header in front of the application (keelsign images keep it).
const MCUBOOT_HEADER_SIZE: u32 = 0x200;

#[entry]
fn main() -> ! {
    let p = embassy_nrf::init(Default::default());

    let mut wdt_config = wdt::Config::default();
    wdt_config.timeout_ticks = 32768 * 5; // timeout seconds
    wdt_config.action_during_sleep = SleepConfig::Run;
    wdt_config.action_during_debug_halt = HaltConfig::Pause;

    let flash = WatchdogFlash::start(Nvmc::new(p.NVMC), p.WDT, wdt_config);
    let flash = Mutex::new(RefCell::new(flash));

    let config = BootLoaderConfig::from_linkerfile_blocking(&flash, &flash, &flash);
    let active_offset = config.active.offset();
    let bl: BootLoader = BootLoader::prepare(config);

    unsafe { bl.load(active_offset + MCUBOOT_HEADER_SIZE) }
}

#[unsafe(no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".HardFault.user"))]
unsafe extern "C" fn HardFault() {
    cortex_m::peripheral::SCB::sys_reset();
}

#[exception]
unsafe fn DefaultHandler(_: i16) -> ! {
    const SCB_ICSR: *const u32 = 0xE000_ED04 as *const u32;
    let irqn = unsafe { core::ptr::read_volatile(SCB_ICSR) } as u8 as i16 - 16;

    panic!("DefaultHandler #{:?}", irqn);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf();
}
```

Build and flash it (this also clears a stale state page and DFU slot):

```sh
cargo build --release
probe-rs erase --chip nRF52840_xxAA
probe-rs download --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/nrf52840-bootloader
```

### RP2350 bootloader

`Cargo.toml`:

```toml
[package]
name = "rp2350-bootloader"
version = "0.0.0"
edition = "2024"
license = "MIT OR Apache-2.0"
publish = false

[workspace]

[dependencies]
embassy-boot-rp = "=0.10.0"
embassy-rp = { version = "=0.10.0", features = ["rp235xa", "critical-section-impl"] }
embassy-sync = "=0.8.0"
embassy-time = "=0.5.1"
cortex-m = { version = "=0.7.9", features = ["inline-asm"] }
cortex-m-rt = "=0.7.7"

[profile.release]
codegen-units = 1
debug = 2
lto = "fat"
opt-level = "z"
```

`.cargo/config.toml`:

```toml
[build]
target = "thumbv8m.main-none-eabihf"
```

`memory.x` (the `SECTIONS` part is `examples/rp2350-hello/memory.x`'s):

```text
/* The RP2350 boot ROM needs the IMAGE_DEF block in the first 4K of flash: the SECTIONS
 * below are the upstream embassy rp235x example's (as in examples/rp2350-hello). */
MEMORY {
    FLASH            : ORIGIN = 0x10000000, LENGTH = 24K
    BOOTLOADER_STATE : ORIGIN = 0x10006000, LENGTH = 4K
    ACTIVE           : ORIGIN = 0x10007000, LENGTH = 512K
    DFU              : ORIGIN = 0x10087000, LENGTH = 516K
    RAM              : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8            : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9            : ORIGIN = 0x20081000, LENGTH = 4K
}

__bootloader_state_start = ORIGIN(BOOTLOADER_STATE) - ORIGIN(FLASH);
__bootloader_state_end = ORIGIN(BOOTLOADER_STATE) + LENGTH(BOOTLOADER_STATE) - ORIGIN(FLASH);

__bootloader_active_start = ORIGIN(ACTIVE) - ORIGIN(FLASH);
__bootloader_active_end = ORIGIN(ACTIVE) + LENGTH(ACTIVE) - ORIGIN(FLASH);

__bootloader_dfu_start = ORIGIN(DFU) - ORIGIN(FLASH);
__bootloader_dfu_end = ORIGIN(DFU) + LENGTH(DFU) - ORIGIN(FLASH);

SECTIONS {
    /* ### Boot ROM info
     *
     * Goes after .vector_table, to keep it in the first 4K of flash
     * where the Boot ROM (and picotool) can find it
     */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH

} INSERT AFTER .vector_table;

/* move .text to start /after/ the boot info */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* ### Picotool 'Binary Info' Entries
     *
     * Picotool looks through this block (as we have pointers to it in our
     * header) to find interesting information.
     */
    .bi_entries : ALIGN(4)
    {
        /* We put this in the header */
        __bi_entries_start = .;
        /* Here are the entries */
        KEEP(*(.bi_entries));
        /* Keep this block a nice round size */
        . = ALIGN(4);
        /* We put this in the header */
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* ### Boot ROM extra info
     *
     * Goes after everything in our program, so it can contain a signature.
     */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH

} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
```

`build.rs`: as for the nRF52840. `src/main.rs`:

```rust
//! A port of the upstream embassy RP2040 bootloader example (embassy-boot-rp-v0.10.0,
//! examples/boot/bootloader/rp) to the RP2350, jumping past the 0x200-byte MCUboot header
//! of keelsign images.
#![no_std]
#![no_main]

use core::cell::RefCell;

use cortex_m_rt::{entry, exception};
use embassy_boot_rp::*;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::Duration;

const FLASH_SIZE: usize = 2 * 1024 * 1024;

/// The MCUboot header in front of the application (keelsign images keep it).
const MCUBOOT_HEADER_SIZE: u32 = 0x200;

#[entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());

    let flash = WatchdogFlash::<FLASH_SIZE>::start(p.FLASH, p.WATCHDOG, Duration::from_secs(8));
    let flash = Mutex::new(RefCell::new(flash));

    let config = BootLoaderConfig::from_linkerfile_blocking(&flash, &flash, &flash);
    let active_offset = config.active.offset();
    let bl: BootLoader = BootLoader::prepare(config);

    unsafe { bl.load(embassy_rp::flash::FLASH_BASE as u32 + active_offset + MCUBOOT_HEADER_SIZE) }
}

#[unsafe(no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".HardFault.user"))]
unsafe extern "C" fn HardFault() {
    cortex_m::peripheral::SCB::sys_reset();
}

#[exception]
unsafe fn DefaultHandler(_: i16) -> ! {
    const SCB_ICSR: *const u32 = 0xE000_ED04 as *const u32;
    let irqn = unsafe { core::ptr::read_volatile(SCB_ICSR) } as u8 as i16 - 16;

    panic!("DefaultHandler #{:?}", irqn);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf();
}
```

```sh
cargo build --release
probe-rs erase --chip RP235x
probe-rs download --chip RP235x target/thumbv8m.main-none-eabihf/release/rp2350-bootloader
```

## The example applications

Each application logs `hello from keelsign boot app A` (`B` with the `b` feature) and
reads the state: on `Swap` it confirms itself (`mark_booted`); on `Revert` it confirms
itself and erases the failed update's header; otherwise it verifies the DFU slot
(`Policy::PqOnly`, the LMS/HSS key of `tests/fixtures/images/keelsign-lms-m32-h5.bin`)
and marks it only if the image is newer than itself (app A is 1.0.0, app B 2.0.0), then
resets. The `soak` feature verifies in a loop and never marks.

Flash app A into the active slot with the probe as the runner (it writes the ELF at
ACTIVE + 0x200 and leaves the state page and the DFU slot alone), from
`examples/nrf52840-boot-app` or `examples/rp2350-boot-app`:

```sh
cargo run --release                     # app A, RTT log in the terminal
cargo run --release --features soak     # P4
```

Write an image into the DFU slot (the bootloader and app A stay):

```sh
probe-rs download --chip nRF52840_xxAA --binary-format bin --base-address 0x47000 IMAGE.bin
probe-rs download --chip RP235x --binary-format bin --base-address 0x10087000 IMAGE.bin
```

Then reset the board (`probe-rs reset --chip ...` or the reset button) and attach to the
RTT log (`probe-rs attach --chip ... target/<triple>/release/<app>`).

## P1 fixture update (NEEDS-HARDWARE)

A valid LMS image is verified, marked and swapped in, on each board. The fixture is
signed with the key the applications trust, version 1.2.3+4 (newer than app A). Its body
is not a program, so after the swap it never runs: the watchdog resets the board and the
bootloader reverts to app A. This proves the mark and the swap; P3 boots a real app B.

1. Flash the bootloader (above), then app A: `cargo run --release`.
2. Expect `hello from keelsign boot app A`, `state Boot: verifying the DFU slot` and
   `no update: Rejected(Parse(BadMagic))` (the DFU slot is empty).
3. Write `tests/fixtures/images/keelsign-lms-m32-h5.bin` into the DFU slot and reset.
4. Expect:
   - `keelsign-embassy: update verified (ImageVersion { major: 1, minor: 2, revision: 3, build_num: 4 }) and marked for swap`
   - `update 1.2.3+4 verified and marked for swap; resetting`
5. The bootloader swaps the slots (tens of seconds on the nRF52840: every page is erased
   and written), jumps into the fixture, and the watchdog resets the board 5 s (nRF) /
   8 s (RP2350) later. The bootloader reverts. Expect
   `hello from keelsign boot app A`, `state Revert: the update was reverted; app A confirmed`
   and `DFU image header erased`.
6. Read the state word: `d0 d0 d0 d0`. Reset once more: `state Boot`,
   `no update: Rejected(Parse(BadMagic))`.

Record the RTT log of steps 2 to 6 for each board. ML-DSA-44 images are DEFERRED to
SHA-169 (ML-DSA verify needs about 98 KB of stack; docs/benchmarks.md).

## P2 tampered and untrusted images (NEEDS-HARDWARE)

Tampered and untrusted images are refused and nothing is written. Make the tampered
copies outside the repository (the committed fixtures are never edited):

```sh
python3 - <<'PY'
src = open("tests/fixtures/images/keelsign-lms-m32-h5.bin", "rb").read()
body = bytearray(src); body[0x200] ^= 0x01        # first body byte
sig = bytearray(src); sig[-1] ^= 0x01             # last byte of the LMS signature TLV
open("/tmp/lms-bad-body.bin", "wb").write(body)
open("/tmp/lms-bad-sig.bin", "wb").write(sig)
PY
```

With app A running, for each image: write it into the DFU slot, reset, and record the
log and the state word.

| Image | Expected log (app A) | State word |
|---|---|---|
| `/tmp/lms-bad-body.bin` | `no update: Rejected(Image(DigestMismatch))` | unchanged (`ff ff ff ff` or `d0 d0 d0 d0`) |
| `/tmp/lms-bad-sig.bin` | `no update: Rejected(SignatureInvalid)` | unchanged |
| `tests/fixtures/images/keelsign-hss2-m32-h5h5.bin` (another key) | `no update: Rejected(KeyNotTrusted)` | unchanged |
| `tests/fixtures/images/keelsign-hybrid-bad-body.bin` | `no update: Rejected(Image(DigestMismatch))` | unchanged |

Each reject is also logged by the adapter as
`keelsign-embassy: update rejected: Rejected(...)`. After every case app A boots again
(`hello from keelsign boot app A`, `state Boot`): the old application keeps running.

## P3 full update with app B (NEEDS-HARDWARE, needs SHA-67; ML-DSA-44 DEFERRED to SHA-169)

App A updates itself to app B. This needs LMS/HSS signing in the host CLI (SHA-67), so it
runs once SHA-67 is merged, with the commands docs/keys.md and docs/signing.md give
then. The signing key is a new LMS/HSS key, not the fixture's.

1. Create the LMS/HSS key with `keelsign keygen` and export its public key (SHA-67). Put
   the 60 raw public-key bytes into `TRUSTED_KEY` in both applications' `src/main.rs`
   for this run only (do not commit it: repo-checks pins `TRUSTED_KEY` to the fixture
   key).
2. Build app B and make a signed image (`cargo install cargo-binutils`,
   `rustup component add llvm-tools`; `imgtool` 2.4.0 as in docs/signing.md):

   ```sh
   cargo build --release --features b
   rust-objcopy -O binary target/thumbv7em-none-eabihf/release/nrf52840-boot-app b.bin
   imgtool sign --header-size 0x200 --pad-header --align 4 --version 2.0.0 \
       --slot-size 0x40000 b.bin b.signed.bin          # RP2350: --slot-size 0x80000
   keelsign sign --key lms.pem b.signed.bin b.keelsign.bin   # SHA-67: LMS/HSS signing
   ```

3. Flash app A (`cargo run --release`, with the same `TRUSTED_KEY`), write
   `b.keelsign.bin` into the DFU slot and reset.
4. Expect from app A: `update 2.0.0+0 verified and marked for swap; resetting`. After
   the swap: `hello from keelsign boot app B` and
   `state Swap: app B confirmed (mark_booted)`; the state word reads `d0 d0 d0 d0`.
5. Reset again: app B boots, `state Boot: verifying the DFU slot` and
   `no update: NotAccepted` (the DFU slot now holds app A, 1.0.0, older than app B).
6. Repeat on the other board. An ML-DSA-44 app B is DEFERRED to SHA-169 (stack).

## P4 reset during verification (NEEDS-HARDWARE)

A reset at any time during verification leaves the state consistent: verification only
reads the DFU slot. (A reset during the marking itself is covered on the host by
`mark::reset_at_any_point_during_mark_leaves_boot_or_swap`, which cuts power after every
write and erase.)

1. Flash the bootloader, write `tests/fixtures/images/keelsign-lms-m32-h5.bin` into the
   DFU slot, then `cargo run --release --features soak`.
2. Expect `soak: verify N start` / `soak: verify N ok (not marked)` lines, about one
   verify every few tens of milliseconds.
3. Reset the board at least 20 times at random moments (`probe-rs reset --chip ...` in a
   loop with random sleeps, or the reset button) while the log runs.
4. After each reset, read the state word: it must be `ff ff ff ff` or `d0 d0 d0 d0`
   (`Boot`), never `f0 f0 f0 f0`; app A must boot again (`hello from keelsign boot app A`)
   and verify `ok` again.
5. Optional: run P1 and cut the power while the bootloader swaps (step 5): embassy-boot's
   swap is power-fail safe and resumes; the board ends in app A with `Revert` handled.

Record the number of resets and the state words for each board.

## Limitations

- The bootloader does not verify again before it swaps: the DFU slot is trusted from
  the application's verify to the next reset (time of check to time of use).
- A revert swaps the previous image back without verifying it; that image was running
  before the update.
- `Updater` needs both partitions on one flash; two-flash layouts use `BlockingUpdater`.
- Verification reads the DFU slot with blocking single-byte reads (`READ_SIZE == 1`).
  The RP2350's async reads are 4 bytes; `Updater` uses the flash's blocking reads for
  the verify and the async ones for the state. Flashes that only read in larger units
  wait for SHA-274.
- A raw application (not an MCUboot image) in the DFU slot is
  `Rejected(Parse(BadMagic))`, as is an erased slot.
- The firmware must not enable embassy-boot's `ed25519-dalek` / `ed25519-salty`
  features: they remove `mark_updated`.
