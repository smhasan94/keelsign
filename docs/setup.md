# Development setup

How to go from a fresh clone to `hello from keelsign` streaming from the development
boards (ticket SHA-32). The boards are listed in [hardware.md](hardware.md).

| Board | Example | Target | probe-rs chip | Probe |
|---|---|---|---|---|
| nRF52840-DK | `examples/nrf52840-hello` | `thumbv7em-none-eabihf` | `nRF52840_xxAA` | on-board J-Link |
| Raspberry Pi Pico 2 W | `examples/rp2350-hello` | `thumbv8m.main-none-eabihf` | `RP235x` | Raspberry Pi Debug Probe |

The host crates (`keelsign`, `keelsign-verify`, `tools/repo-checks`) need only the
toolchain; the tools below are for the embedded examples.

## Toolchain

1. Install [rustup](https://rustup.rs).
2. Use stable Rust 1.91 or newer (`rustup update stable`).
3. Add the two embedded targets:

   ```sh
   rustup target add thumbv7em-none-eabihf thumbv8m.main-none-eabihf
   ```

Each example also has its own `rust-toolchain.toml` (`channel = "stable"`, its target,
`rustfmt` and `clippy`), so rustup installs the target automatically the first time you
build inside that directory.

## Tools

Install the pinned versions from source (this is the tested path; probe-rs takes several
minutes to compile):

```sh
cargo install probe-rs-tools --version 0.32.0 --locked
cargo install flip-link --version 0.1.12 --locked
```

- `probe-rs-tools` provides `probe-rs` (flash, run, RTT/defmt), `cargo-flash` and
  `cargo-embed`.
- `flip-link` is a linker wrapper that places the stack below `.data`/`.bss`, so a stack
  overflow faults instead of silently corrupting memory.

Alternative (unpinned): the prebuilt probe-rs installer from
<https://probe.rs/docs/getting-started/installation/>, for example on Linux and macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/probe-rs/probe-rs/releases/latest/download/probe-rs-tools-installer.sh | sh
```

It installs the latest release, which may differ from the version tested here.

Check the install:

```console
$ probe-rs --version
probe-rs 0.32.0 (git commit: crates.io)
```

`flip-link --version` prints an error about `rust-lld` when run on its own; that is
expected, because cargo supplies the linker path during a build. `which flip-link` is
enough to check it is on `PATH`.

### C library tools (keelsign-ffi, SHA-60)

Only needed to work on `keelsign-ffi` ([ffi.md](ffi.md)):

```sh
cargo install cbindgen --version 0.29.4 --locked
rustup toolchain install nightly-2026-09-29
rustup component add --toolchain nightly-2026-09-29 miri rust-src
```

- `cbindgen` 0.29.4 regenerates and checks `keelsign-ffi/include/keelsign.h`
  (`repo_checks::ffi::keelsign_h_matches_cbindgen_output` is ignored without it).
- Miri on the pinned nightly runs the pointer-contract unit tests (the command is in
  [ffi.md](ffi.md#miri)).
- A C compiler (`cc`; set `CC` to choose another) with UBSan builds the C harness that
  `cargo test -p repo-checks --test ffi` runs. On macOS the Xcode or Command Line Tools
  clang works; when the Command Line Tools' SDK does not match the compiler, linking fails
  until `SDKROOT=$(xcrun --sdk macosx --show-sdk-path)` is set (the repo-check sets it
  itself when it is unset). AddressSanitizer hangs on macOS, so the repo-check uses UBSan
  alone there and ASan + UBSan on Linux; `KEELSIGN_FFI_SANITIZE` overrides it.

## Probe permissions

- **Linux**: install the probe-rs udev rules so a normal user can open the probes, then
  reload them and replug the probe:

  ```sh
  curl -LO https://probe.rs/files/69-probe-rs.rules
  sudo cp 69-probe-rs.rules /etc/udev/rules.d/
  sudo udevadm control --reload && sudo udevadm trigger
  ```

  The rules grant access to the `plugdev` group; add yourself with
  `sudo usermod -aG plugdev $USER` and log in again if you are not already a member.
- **macOS**: nothing to do.
- **Windows**: no permissions step; if a probe is not listed, see the driver notes at
  <https://probe.rs/docs/getting-started/probe-setup/>.

## Runner configuration

Each example is a standalone Cargo project (its own `[workspace]`, `Cargo.lock` and
`target/`), excluded from the root workspace so `cargo test --workspace` at the root stays
host-only. Its `.cargo/config.toml` makes `cargo run` flash the board. For the nRF52840:

```toml
[target.thumbv7em-none-eabihf]
runner = "probe-rs run --chip nRF52840_xxAA"
rustflags = ["-C", "linker=flip-link"]

[build]
target = "thumbv7em-none-eabihf"

[env]
DEFMT_LOG = "info"
```

- `runner`: cargo calls this with the built ELF. `probe-rs run` flashes it, resets the
  chip and prints the defmt log it reads over RTT until you press Ctrl-C.
- `rustflags`: link through `flip-link`.
- `[build] target`: plain `cargo build` / `cargo run` in the directory builds for the board.
- `DEFMT_LOG`: the compile-time defmt log level (`trace`, `debug`, `info`, `warn`,
  `error`).

`examples/rp2350-hello/.cargo/config.toml` is the same with
`[target.thumbv8m.main-none-eabihf]` and `--chip RP235x`.

The linker scripts come from each example's `build.rs`: it copies `memory.x` to the build
directory and passes `--nmagic`, `-Tlink.x` (cortex-m-rt) and `-Tdefmt.x` (defmt).

## Flash and run

Wiring:

- **nRF52840-DK**: connect USB to the interface MCU (J-Link) connector on the short edge
  of the board (not the "nRF USB" connector), and set the power switch to ON.
- **Pico 2 W**: connect the Debug Probe's `D` (SWD) port to the Pico 2 W's 3-pin debug
  header, connect the Debug Probe to the host by USB, **and** connect the Pico 2 W's own
  USB port to the host (or another supply) to power it. The probe does not power the
  target.

Then:

```sh
cd examples/nrf52840-hello   # or examples/rp2350-hello
cargo run
```

`cargo run` builds the debug profile; `cargo run --release` flashes the smaller optimised
build (both keep debug info for defmt locations).

Expected output (sizes, timestamps and paths will differ; a debug build flashes roughly
55 KiB, a release build less):

```text
      Erasing ✔ 100% [####################]  56.00 KiB @ ...
  Programming ✔ 100% [####################]  56.00 KiB @ ...
     Finished in ...
0.000000 [INFO ] hello from keelsign (nRF52840-DK) (nrf52840_hello src/main.rs:...)
1.000000 [INFO ] tick 1 (nrf52840_hello src/main.rs:...)
2.000000 [INFO ] tick 2 (nrf52840_hello src/main.rs:...)
```

On the Pico 2 W the first line is `hello from keelsign (Pico 2 W / RP2350)`. On the DK,
LED1 toggles once a second. The Pico 2 W's LED is wired through the CYW43 radio, so this
example does not blink it. Stop with Ctrl-C.

## Probe detection

With the probe(s) connected:

```sh
probe-rs list    # lists the J-Link and/or the Debug Probe (CMSIS-DAP)
probe-rs info    # connects to the probe and auto-detects the chip on it
```

`probe-rs info` detects the chip itself (probe-rs 0.32.0 ignores `--chip` here, with a
warning). If both probes are connected, `probe-rs info` and `probe-rs run` ask which to
use; pass `--probe <VID:PID>` (from `probe-rs list`) to choose one without the prompt,
for example `probe-rs info --probe <VID:PID>`.

## Fresh-clone walkthrough

1. `git clone https://github.com/smhasan94/keelsign && cd keelsign`
2. Install the [toolchain](#toolchain) and the two targets.
3. Install [probe-rs-tools and flip-link](#tools); check `probe-rs --version` prints
   `probe-rs 0.32.0`.
4. On Linux, install the [udev rules](#probe-permissions).
5. Host checks: `cargo test --workspace --locked`.
6. Local tool checks: `cargo test -p repo-checks --locked -- --ignored` (checks the targets,
   probe-rs 0.32.0, flip-link on `PATH`, cross-builds both examples and both bench
   projects, and runs the flash-size script; it also runs a publish dry run and the ML-DSA
   fixture regeneration check, which need network access). The ignored
   `three_run_logs_consistent_within_5_percent` fails with "no logs yet" until the board
   logs are saved ([benchmarks.md](benchmarks.md#three-run-consistency)).
7. Connect the nRF52840-DK, run `probe-rs list`, then
   `cd examples/nrf52840-hello && cargo run`; confirm `hello from keelsign` and
   the ticks, and LED1 blinking.
8. Wire the Pico 2 W and Debug Probe as in [Flash and run](#flash-and-run), run
   `probe-rs list`, then `cd examples/rp2350-hello && cargo run`; confirm
   `hello from keelsign` and the ticks.

## Troubleshooting

- **nRF52840: APPROTECT / "the chip is locked"**: newer nRF52840 revisions (and boards
  flashed with protected firmware) have access port protection enabled. Erase the whole
  chip to unlock it; this deletes everything on it:
  `probe-rs erase --chip nRF52840_xxAA --allow-erase-all`.
- **RP2350 flashes but does not start**: the RP2350 boot ROM only runs an image that has a
  valid IMAGE_DEF block in the first 4 KiB of flash. embassy-rp emits it into
  `.start_block`, and `examples/rp2350-hello/memory.x` places that section right after the
  vector table. Keep that `memory.x` as it is (it is a verbatim copy of upstream embassy's).
- **RP2350: architecture (ARCHSEL)**: the RP2350 has both Arm Cortex-M33 and Hazard3
  RISC-V cores and the boot ROM picks one from the image. This example is an Arm image
  (`thumbv8m.main-none-eabihf`, chip `RP235x`). If the board still holds a RISC-V image
  and probe-rs cannot attach, hold BOOTSEL while plugging in the Pico 2 W and try again,
  or erase it with `probe-rs erase --chip RP235x`.
- **Only "hello" but no ticks, or no log at all**: check `DEFMT_LOG` in the example's
  `.cargo/config.toml` (or your shell environment, which overrides it). `trace`/`debug`
  messages are compiled out at `info`. If a change does not take effect, `cargo clean`
  and rebuild.
- **`linker 'flip-link' not found`**: install it (`cargo install flip-link --version
  0.1.12 --locked`) and make sure `~/.cargo/bin` is on `PATH`.
- **`probe-rs: command not found` on `cargo run`**: install probe-rs-tools, see
  [Tools](#tools).
- **Linux: probe listed but "permission denied"**: install the
  [udev rules](#probe-permissions) and replug the probe.

## On-target tests (embedded-test)

On-target tests use [`embedded-test`](https://crates.io/crates/embedded-test) `0.7.2`
(`default-features = false`, features `semihosting`, `panic-handler`, `defmt`), run
through the same `probe-rs run` runner, which detects an embedded-test binary and runs
each test case after a reset. The tests are synchronous: no embassy executor, so no
`embassy-010` feature, and embedded-test's panic handler replaces `panic-probe`.

The first on-target tests are the SHA-34 ML-DSA KATs and benchmarks in
`benches/nrf52840-mldsa` and `benches/rp2350-mldsa` (standalone projects like the
examples). Their `build.rs` passes the linker scripts with `cargo:rustc-link-arg=` (not
`-bins`) and adds `-Tembedded-test.x`, so the test binary keeps its test-case section.
Run them from the project directory with:

```sh
cd benches/nrf52840-mldsa   # or benches/rp2350-mldsa
cargo test --release
```

The exact commands, the measurement method and the results are in
[benchmarks.md](benchmarks.md).

## CI

`.github/workflows/ci.yml` has three jobs:

- `ci`: host fmt, clippy and tests for the root workspace (including the host ML-DSA
  KATs in `benches/mldsa-kat`), the packaging repo-checks (`--test packaging -- --ignored`)
  and the publish dry runs. Since SHA-60 also the `keelsign.h` drift check (cbindgen
  0.29.4), the C harness against `libkeelsign.a` under ASan + UBSan and Miri on
  `keelsign-ffi` (nightly-2026-09-29).
- `verify-cross`: `keelsign-verify` and (SHA-60) `keelsign-ffi`'s `libkeelsign.a` for
  both Cortex-M targets in four feature states, with the `staticlib_sizes.py --check`
  symbol rules.
- `cross-build`: for each example (`nrf52840-hello` on `thumbv7em-none-eabihf`,
  `rp2350-hello` on `thumbv8m.main-none-eabihf`) it installs the target and flip-link and
  runs `cargo fmt --check`, `cargo clippy --locked --target <triple> -- -D warnings` and
  `cargo build --release --locked --target <triple>` in the example directory. For each
  bench project (`benches/nrf52840-mldsa`, `benches/rp2350-mldsa`) it runs
  `cargo fmt --check`, `cargo clippy --locked --target <triple> --all-targets -- -D warnings`,
  `cargo test --no-run --release --locked --target <triple>` (builds the on-target test
  binary without running it) and `cargo build --release --locked --target <triple> --bins`.

CI never flashes a board. The ignored repo-checks tests (`toolchain::*`,
`examples::*_cross_builds`, `benches::*_cross_builds`, `benches::flash_sizes_script_runs`)
are for local machines; CI covers the cross-builds in the `cross-build` job instead.
