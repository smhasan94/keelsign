# MCUboot integration (SHA-62)

keelsign plugs into MCUboot as an extra gate: MCUboot's `boot_image_check_hook` reads
each image it is about to validate through `libkeelsign.a` and rejects it unless keelsign's
post-quantum (LMS/HSS) signature verifies against a key built into the bootloader. When it
does, MCUboot's own validation still runs unchanged: the SHA256 TLV, MCUboot's classical
signature (ECDSA P-256, Ed25519 or RSA, made by imgtool), the security counter and the
dependencies. Images keep MCUboot's format; keelsign adds its TLVs (0x4BA0-0x4BA3,
[image-format.md](image-format.md)) next to imgtool's.

This document covers the Zephyr module in this repository (`zephyr/`, `sysbuild/`,
`cmake/`), the glue in `mcuboot/`, and the sample `samples/keelsign_hello` for the
nRF52840-DK: setup, build, configuration, sizes, and the on-board checks P1-P4.

## Why the image-check hook, not `MCUBOOT_USE_CUSTOM_CRYPTO`

MCUboot has two extension points that sound alike:

- `MCUBOOT_USE_CUSTOM_CRYPTO` (MCUboot v2.5.0-rc1 `bcb0fe5a` and later; not in v2.4.0)
  replaces MCUboot's **crypto backend**: the SHA256, ECDSA, HMAC, AES-CTR and ECDH
  primitives come from a platform header instead of TinyCrypt, Mbed TLS or PSA. MCUboot's
  own `image_validate.c` still decides which signature TLVs it checks, and none of them is
  keelsign's. Using it would make keelsign replace MCUboot's classical crypto, the
  opposite of what keelsign is for, and it has no Zephyr Kconfig.
- `MCUBOOT_IMAGE_ACCESS_HOOKS` (Zephyr: `CONFIG_BOOT_IMAGE_ACCESS_HOOKS`) lets a port
  run code before MCUboot validates a slot: `fih_ret boot_image_check_hook(int
  img_index, int slot)` is called from `boot_validate_slot()` after the header check and
  before `bootutil_img_validate()`, and from serial recovery. `FIH_BOOT_HOOK_REGULAR`
  lets MCUboot's validation run, `FIH_FAILURE` rejects the image. The prototype is the
  same in v2.4.0 (`6d3b3d2`) and v2.5.0-rc1 (`bcb0fe5a`).

keelsign uses the second. `mcuboot/keelsign_mcuboot_hooks.c` (MIT OR Apache-2.0):

- opens the slot's flash area and hands it to `keelsign_verify_cb` as a
  `keelsign_reader_t` over `flash_area_read` ([ffi.md](ffi.md#callback-reader)), with the
  trusted keys and the policy of the generated key table;
- on `KEELSIGN_OK` logs `keelsign: image 0 slot 0 verified (pq key 0, ed25519 key
  4294967295)` at INF and returns `FIH_BOOT_HOOK_REGULAR`;
- on any error logs `keelsign: image 0 slot 0 rejected: status N` at ERR (N is a
  `keelsign_status_t`, [ffi.md](ffi.md#status-codes)) and returns `FIH_FAILURE`; a flash
  area it cannot open or read is a reject too (`status 42`);
- never returns `FIH_SUCCESS`, which would skip MCUboot's own checks;
- defines the rest of the `MCUBOOT_IMAGE_ACCESS_HOOKS` set (MCUboot calls all of them)
  with MCUboot's normal behaviour.

The hook reads the slot, then MCUboot reads it again for its own checks: MCUboot's usual
two-pass model (it hashes the slot in `bootutil_img_validate()` after the header check
read it too).

### Swap modes

Where the image starts in a slot depends on MCUboot's upgrade mode. With swap using
offset (`CONFIG_BOOT_SWAP_USING_OFFSET`, sysbuild's default `SB_CONFIG_MCUBOOT_MODE` in
Zephyr v4.4.2 and the sample's mode) an update in the secondary slot starts one sector
into the slot (`swap_offset.c`), and MCUboot validates it from there
(`boot_get_state_secondary_offset()`, `image_validate.c`, `bootutil_img_hash.c`). The
hook reads the slot from the same offset: under `MCUBOOT_SWAP_USING_OFFSET` it asks
`boot_get_state_secondary_offset(boot_get_loader_state(), fap)`, which is the sector
offset for the secondary slot of the image being validated and 0 for the primary slot
(MCUboot matches the area by the pointer `flash_area_open()` returns, an entry of
Zephyr's static flash map). Serial recovery sets the same offset before it calls the hook
(`boot_serial.c`). An offset at or past the end of the slot is a reject (`status 40`,
`KEELSIGN_ERR_READ_OUT_OF_BOUNDS`). In every other mode (scratch, move, overwrite-only,
direct-XIP, single slot) the image starts at offset 0 and the hook reads it there. The
hook only runs for a slot whose header MCUboot has already read and accepted at that
offset (`boot_check_header_valid()`, or the header magic in serial recovery); it does
not rely on that, and an erased or foreign slot that does reach it is rejected
(`status 30`, `KEELSIGN_ERR_PARSE_BAD_MAGIC`). The host harness checks both builds
([Host hook harness](#host-hook-harness)).

## Pins

| What | Pin |
|---|---|
| Zephyr | v4.4.2, `dccb09599635bdff17633fa7e9dab014b91dce90` (`west.yml`) |
| MCUboot | v2.4.0, `6d3b3d2c38ab20c242e5b9abb04d050086383eb2` (pinned by Zephyr v4.4.2) |
| MCUboot, compile check only | v2.5.0-rc1, `bcb0fe5a66c6b795817fa3280ce991bfc128af72` |
| Zephyr SDK | 1.0.1 (arm-zephyr-eabi-gcc 14.3.0), minimal + `arm-zephyr-eabi` |
| west | 1.5.0 |
| imgtool | 2.4.0 |
| Rust target | `thumbv7em-none-eabi` (MCUboot on the nRF52840 is soft-float) |

## Setup

The sample needs a west workspace: a directory holding this repository as `keelsign`
plus Zephyr, MCUboot and a few modules next to it. `scripts/zephyr-setup.sh` makes it in
the directory that holds your clone, and installs everything there (a Python venv with
west and imgtool, the Zephyr SDK with SHA256-checked archives), nothing system-wide. It
refuses a directory that is a git work tree or holds anything else, so start from a new
one:

```sh
mkdir keelsign-ws && cd keelsign-ws
git clone https://github.com/smhasan94/keelsign
keelsign/scripts/zephyr-setup.sh
```

It needs git, curl, tar with xz, python3 3.10 or newer, cmake 3.20 or newer and ninja
(macOS arm64 or Linux x86_64 hosts), takes a few minutes and about 2 GB, and can be
re-run (each step is skipped when done). Rust needs the soft-float Cortex-M4 target:

```sh
rustup target add thumbv7em-none-eabi
```

Then, in each shell, from `keelsign-ws/keelsign` (the script prints the same lines with
absolute paths; `scripts/zephyr_sample_ci.sh` sets them itself):

```sh
export ZEPHYR_SDK_INSTALL_DIR="$PWD/../.zephyr-sdk-1.0.1" ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export PATH="$PWD/../.venv/bin:$PATH"
```

With an existing Zephyr SDK 1.0.1 (with `arm-zephyr-eabi`), set `ZEPHYR_SDK_INSTALL_DIR`
before running the script and it is used instead of a download; with `west` already on
`PATH`, no venv is made (your Python then needs Zephyr's requirements and imgtool 2.4.0).

### Workspace layout

```text
keelsign-ws/
├── keelsign/              this repository (west manifest repository and Zephyr module)
├── zephyr/                Zephyr v4.4.2
├── bootloader/mcuboot/    MCUboot v2.4.0
├── modules/               hal/cmsis, hal/cmsis_6, hal/nordic, crypto/mbedtls, crypto/tf-psa-crypto
├── .west/                 west's configuration
├── .venv/                 west 1.5.0, imgtool 2.4.0, Zephyr's Python requirements
└── .zephyr-sdk-1.0.1/     Zephyr SDK 1.0.1 with arm-zephyr-eabi
```

## Build

All commands run in `keelsign-ws/keelsign`. `scripts/zephyr_sample_ci.sh` runs exactly
these (its steps are named after the subsections; `scripts/zephyr_sample_ci.sh all`
runs them all, as the CI job `zephyr-sample` does).

### Make a signing key (`setup-key`)

The sample signs with `samples/keelsign_hello/keelsign-dev.pem`, a stateful LMS/HSS key
(LMS_SHA256_M32_H10, 1,024 signatures) you make once and never commit (`.gitignore`
covers it, its `.state` and its `.journal`):

```sh
cargo build -p keelsign --release --locked
target/release/keelsign keygen --alg lms-sha256-m32-h10 --out samples/keelsign_hello/keelsign-dev.pem
```

Every build that relinks the application signs it again and uses up one leaf; read
[lms.md](lms.md#rules-for-handling-a-key) before using a key for real firmware. For a
product, keep the private key off build machines and sign release images with
`keelsign sign` ([signing.md](signing.md)).

### Build MCUboot and the application (`build`)

```sh
west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build
```

sysbuild builds two images:

- `build/mcuboot/zephyr/zephyr.hex`: MCUboot with keelsign (hooks on, TLV allow list
  off, the key table made from `build/keelsign.pub.pem`, which `keelsign pubkey`
  exported from `keelsign-dev.pem`), and MCUboot's own ECDSA P-256 check with
  `root-ec-p256.pem`;
- `build/keelsign_hello/zephyr/zephyr.signed.keelsign.hex` (and `.bin`): the application,
  signed by imgtool (`zephyr.signed.bin`: SHA256, KEYHASH and ECDSA TLVs) and then by
  keelsign (key ID 0x4BA0 and LMS/HSS signature 0x4BA3 added). `west flash` and the
  procedures below program this file.

The first build also compiles the keelsign CLI (`build/keelsign-cargo-host`) and
`libkeelsign.a` (`build/mcuboot/keelsign-cargo`) with cargo.

**`root-ec-p256.pem` is MCUboot's public development key** (the build warns about it):
set `SB_CONFIG_BOOT_SIGNATURE_KEY_FILE` to your own key for anything but development.

### Check both signatures on the host (`verify`)

```sh
imgtool verify --key ../bootloader/mcuboot/root-ec-p256.pem build/keelsign_hello/zephyr/zephyr.signed.keelsign.bin
target/release/keelsign verify --pub build/keelsign.pub.pem build/keelsign_hello/zephyr/zephyr.signed.keelsign.bin
```

imgtool prints `Image was correctly validated`; keelsign prints `verified:` and the
key ID.

### Bad images for the on-board checks (`variants`)

```sh
python3 scripts/mcuboot_variants.py --keelsign target/release/keelsign build
```

writes, from the build above, `build/variants/tampered.{bin,hex}` (one body byte
flipped), `wrong-key.{bin,hex}` (re-signed by a fresh key the bootloader does not trust,
`build/variants/other.pem`) and `bad-ecdsa.{bin,hex}` (imgtool's ECDSA signature
corrupted, keelsign's intact), all at slot 0.

## Flash and run

The DK's on-board debugger (or a Raspberry Pi Debug Probe on its debug header) and
probe-rs 0.32.0 ([setup.md](setup.md)); the UART is the DK's VCOM port (USB), 115200
baud 8N1. The Zephyr runner for this board does not use probe-rs, so flash the hex files
directly:

```sh
probe-rs erase --chip nRF52840_xxAA
probe-rs download --chip nRF52840_xxAA --binary-format hex build/mcuboot/zephyr/zephyr.hex
probe-rs download --chip nRF52840_xxAA --binary-format hex build/keelsign_hello/zephyr/zephyr.signed.keelsign.hex
probe-rs reset --chip nRF52840_xxAA
```

## Kconfig reference

Image options (`zephyr/Kconfig`), set by sysbuild in the sample:

| Option | Image | Meaning |
|---|---|---|
| `CONFIG_KEELSIGN` | MCUboot | the hook, the key table and `libkeelsign.a`; needs `CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y` and `CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=n` (the build stops otherwise) |
| `CONFIG_KEELSIGN_POLICY_PQ_ONLY` (default) / `CONFIG_KEELSIGN_POLICY_HYBRID` | MCUboot | the policy ([Policies](#policies)) |
| `CONFIG_KEELSIGN_PUBLIC_KEY_FILE` | MCUboot | public key files (`keelsign pubkey` output, PEM or DER), separated by spaces: 1-8 LMS/HSS keys, plus 1-8 Ed25519 keys for the hybrid policy |
| `CONFIG_KEELSIGN_LIBRARY` | MCUboot | a prebuilt `libkeelsign.a`; empty: cargo builds it |
| `CONFIG_KEELSIGN_RUST_TARGET` | MCUboot | Rust target of `libkeelsign.a`; empty: from the CPU (`thumbv6m`/`thumbv7m`/`thumbv7em`/`thumbv8m.base`/`thumbv8m.main`, `hf` only with `CONFIG_FP_HARDABI`) |
| `CONFIG_KEELSIGN_MIN_MAIN_STACK` | MCUboot | warn below this `CONFIG_MAIN_STACK_SIZE` (12288; 16384 hybrid) |
| `CONFIG_KEELSIGN_SIGN_IMAGE` | application | sign with keelsign after imgtool (needs `CONFIG_BOOTLOADER_MCUBOOT`) |
| `CONFIG_KEELSIGN_SIGNATURE_KEY_FILE` | application | the LMS/HSS private key |
| `CONFIG_KEELSIGN_CLI` | application | the keelsign CLI; empty: cargo builds it |

`CONFIG_KEELSIGN` in a non-MCUboot image stops the build. MCUboot's own symbols exist
only in the MCUboot image, so the module's Kconfig never depends on them; the checks are
in `zephyr/CMakeLists.txt`.

sysbuild options (`sysbuild/Kconfig`, in the application's `sysbuild.conf`):

| Option | Meaning |
|---|---|
| `SB_CONFIG_KEELSIGN` | keelsign in the `mcuboot` image and signing of the application (needs `SB_CONFIG_BOOTLOADER_MCUBOOT`) |
| `SB_CONFIG_KEELSIGN_SIGNATURE_KEY_FILE` | the LMS/HSS private key, relative to the application directory (default `keelsign-dev.pem`); the bootloader trusts its public key |
| `SB_CONFIG_KEELSIGN_POLICY_PQ_ONLY` / `SB_CONFIG_KEELSIGN_POLICY_HYBRID` | the policy; hybrid needs `SB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519` and trusts the public key of `SB_CONFIG_BOOT_SIGNATURE_KEY_FILE` as the Ed25519 key |
| `SB_CONFIG_KEELSIGN_LIBRARY`, `SB_CONFIG_KEELSIGN_CLI` | passed on as `CONFIG_KEELSIGN_LIBRARY` / `CONFIG_KEELSIGN_CLI` |

## Policies

- **`KEELSIGN_POLICY_PQ_ONLY`** (default): the image needs keelsign's key ID and
  LMS/HSS signature by a trusted key. It works with any MCUboot signature type
  (`SB_CONFIG_BOOT_SIGNATURE_TYPE_*`, including none), and MCUboot keeps checking its
  own. The sample uses ECDSA P-256 + `PQ_ONLY`, so classical signing is unchanged.
- **`KEELSIGN_POLICY_HYBRID`**: keelsign also checks MCUboot's Ed25519 pair (KEYHASH +
  ED25519, made by imgtool) over the same digest. For MCUboot built with
  `SB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519`; `libkeelsign.a` gets the `ed25519` feature.
  The hybrid MCUboot does not fit the sample's 64 KB boot partition: it needs about
  100 KB ([benchmarks.md](benchmarks.md#mcuboot-with-keelsign-sha-62)), so the sample
  only compiles it (`hybrid-build`):

  ```sh
  west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build-hybrid --cmake-only -- -DSB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y -DSB_CONFIG_KEELSIGN_POLICY_HYBRID=y
  cmake --build build-hybrid/mcuboot --target keelsign_mcuboot keelsign_cargo
  ```

- **No classical-only policy.** In a bootloader that already verifies its classical
  signature, keelsign's `KEELSIGN_POLICY_CLASSICAL_ONLY` would be a second, redundant
  Ed25519 check with no post-quantum guarantee; a device that wants classical signatures
  only does not enable keelsign.
- **No ML-DSA.** ML-DSA verify needs 98-158 KB of stack ([benchmarks.md](benchmarks.md)),
  more than MCUboot has; the module offers LMS/HSS only.

A CNSA 2.0 (single-tree LMS only) switch is not in the C ABI yet.

## TLV allow list

MCUboot rejects an image with an unprotected TLV that is not on its compiled-in list
(`allowed_unprot_tlvs` in `image_validate.c`, `CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y`,
the default), and keelsign's TLVs are not on it. The list cannot be extended without a
fork, so keelsign needs `CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=n`: sysbuild sets it with
`SB_CONFIG_KEELSIGN`, and an MCUboot image with keelsign and the list on stops at
configure time (`allow-list-refused`, MCUboot built on its own):

```sh
target/release/keelsign pubkey --key samples/keelsign_hello/keelsign-dev.pem --out target/keelsign-dev.pub.pem --force
west build -b nrf52840dk/nrf52840 ../bootloader/mcuboot/boot/zephyr -d build-allow-list -p always --cmake-only -- -DCONFIG_KEELSIGN=y -DCONFIG_BOOT_IMAGE_ACCESS_HOOKS=y -DCONFIG_KEELSIGN_PUBLIC_KEY_FILE=\"$PWD/target/keelsign-dev.pub.pem\"
```

fails with `keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs
0x4BA0-0x4BA3 (image_validate.c allowed_unprot_tlvs); set it to n`. With the list off
MCUboot still ignores TLVs it does not parse, and keelsign checks its own.

## Signing

`cmake/keelsign_signing.cmake` is the application's signing script
(`CONFIG_KEELSIGN_SIGN_IMAGE`): Zephyr's own `cmake/mcuboot.cmake` runs first (imgtool,
unchanged), then

```text
keelsign sign --key <CONFIG_KEELSIGN_SIGNATURE_KEY_FILE> --force zephyr.signed.bin zephyr.signed.keelsign.bin
objcopy -I binary -O ihex --change-addresses <slot 0 address> zephyr.signed.keelsign.bin zephyr.signed.keelsign.hex
```

keelsign signs the unpadded imgtool output (it refuses padded images). The
`.signed.keelsign` files become the ones `west flash` programs. The commands run only
when the application relinks, and each run uses one LMS/HSS leaf.

## Partitions

MCUboot plus keelsign's LMS/HSS verifier is 48,564 B, which leaves 588 B in the board's
default 48 KB boot partition. The sample's `boards/nrf52840dk_nrf52840.overlay` makes it
64 KB:

| Partition | Offset | Size |
|---|---|---|
| `boot_partition` | 0x0 | 0x10000 (64 KB) |
| `slot0_partition` | 0x10000 | 0x74000 (464 KB) |
| `slot1_partition` | 0x84000 | 0x74000 (464 KB) |
| `storage_partition` | 0xf8000 | 0x8000 (unchanged) |

`sysbuild/mcuboot.overlay` includes the same file for the MCUboot image and links MCUboot
into `boot_partition` (a sysbuild `mcuboot.overlay` replaces MCUboot's own `app.overlay`,
which does only that), so both images always agree.

## Stack

keelsign runs on MCUboot's main thread: about 5 KB of buffers and key tables
(`KEELSIGN_TLV_BUF_LEN` 4 KiB, the 256-byte chunk, the key tables) plus about 1.5 KB for
LMS/HSS (5 KB more for Ed25519 in the hybrid policy), on top of what MCUboot itself uses.
The sample raises `CONFIG_MAIN_STACK_SIZE` from MCUboot's 10240 to 16384
(`sysbuild/mcuboot.conf`); the module warns below `CONFIG_KEELSIGN_MIN_MAIN_STACK`.
Measured on-target stack and cycles of the C entry points are SHA-315.

## Sizes

[benchmarks.md](benchmarks.md#mcuboot-with-keelsign-sha-62) records MCUboot's flash and
static RAM with and without keelsign (+18,996 B flash, +0 B static RAM). The stock build
is the same sample with keelsign off (`stock-build`):

```sh
west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build-stock -- -DSB_CONFIG_KEELSIGN=n
```

and `sizes` prints the table from both MCUboot ELFs:

```sh
python3 scripts/mcuboot_sizes.py build-stock/mcuboot/zephyr/zephyr.elf build/mcuboot/zephyr/zephyr.elf
```

## Host hook harness

`mcuboot/hooktest/` compiles the glue against the pinned MCUboot headers as a port would
(its own `mcuboot_config.h`, logging, flash map and `sysflash.h`; `flash_stub.c` backs the
slots with files) and runs `boot_image_check_hook` on the image fixtures: good, tampered,
wrong-key, hybrid and unopenable-slot cases, and a compile against v2.5.0-rc1. It builds
the glue twice, with and without `MCUBOOT_SWAP_USING_OFFSET`; in the first build
`--slot-offset` places the secondary-slot image one sector in and the harness's
`boot_get_state_secondary_offset()` reports that offset, as MCUboot's loader does
([Swap modes](#swap-modes)).
`scripts/fetch_mcuboot.py` clones MCUboot at the pin into `target/` (or uses
`KEELSIGN_MCUBOOT_DIR`, for example the workspace's `bootloader/mcuboot`, offline):

```sh
cargo test -p repo-checks --locked --test mcuboot -- --ignored hook_
```

CI runs the `hook_harness` tests in the `ci` job (step `MCUboot hook harness (network)`).
The MCUboot simulator run with the hook is SHA-328.

## Other MCUboot ports

The glue needs nothing Zephyr-specific: compile `mcuboot/keelsign_mcuboot_hooks.c` and
a key table from `scripts/keelsign_embed_keys.py` with MCUboot's `bootutil/include`,
your port's headers, `mcuboot/include` and `keelsign-ffi/include`, link
`libkeelsign.a` ([ffi.md](ffi.md#build)) for your CPU, and define
`MCUBOOT_IMAGE_ACCESS_HOOKS` without `MCUBOOT_USE_TLV_ALLOW_LIST`. STM32U5 and ESP-IDF
ports are SHA-63.

## Troubleshooting

- `keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs ...`: see
  [TLV allow list](#tlv-allow-list).
- `signing key .../keelsign-dev.pem does not exist`: make it ([setup-key](#make-a-signing-key-setup-key)).
- `ld: ... uses VFP register arguments` or a similar float-ABI error: `libkeelsign.a`
  was built for `eabihf` but MCUboot is soft-float; leave `CONFIG_KEELSIGN_RUST_TARGET`
  empty or set the `eabi` target, and `rustup target add thumbv7em-none-eabi`.
- `region 'FLASH' overflowed` in the MCUboot image: the boot partition is too small
  ([Partitions](#partitions); the hybrid policy needs about 100 KB).
- No `keelsign:` line on the UART: MCUboot logs at WRN by default; the `verified` line
  is INF (`CONFIG_MCUBOOT_LOG_LEVEL_INF=y` in `sysbuild/mcuboot.conf`). The reject line is
  ERR and always shows.
- The board shows `rejected: status 70` after a rebuild: the application was rebuilt but
  only MCUboot's hex was flashed, or the other way round; flash both.

## On-board procedures

These need an nRF52840-DK and a person at the board (NEEDS-HARDWARE): CI builds every
file they use, nobody flashes a board in CI. Build first (`setup-key`, `build`,
`variants`), use the [Flash and run](#flash-and-run) commands, and record the UART log of
each procedure in the pull request. Each starts from an erased chip.

### P1: good image boots (NEEDS-HARDWARE)

Flash `build/mcuboot/zephyr/zephyr.hex` and
`build/keelsign_hello/zephyr/zephyr.signed.keelsign.hex`, reset. Pass: the UART shows, in
this order,

```text
I: Starting bootloader
I: keelsign: image 0 slot 0 verified (pq key 0, ed25519 key 4294967295)
I: Jumping to the first image slot
hello from keelsign_hello on nrf52840dk/nrf52840, linked at 0x10000
keelsign_hello tick 1
```

(other MCUboot lines in between are fine).

### P2: tampered image rejected (NEEDS-HARDWARE)

Flash MCUboot and `build/variants/tampered.hex` (one body byte flipped), reset. Pass:

```text
E: keelsign: image 0 slot 0 rejected: status 70
E: Image in the primary slot is not valid!
E: Unable to find bootable image
```

and no `hello from keelsign_hello`. Status 70 is `KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH`.

### P3: wrong key rejected (NEEDS-HARDWARE)

Flash MCUboot and `build/variants/wrong-key.hex` (signed by `build/variants/other.pem`,
which the bootloader does not trust), reset. Pass: `E: keelsign: image 0 slot 0
rejected: status 15` (`KEELSIGN_ERR_KEY_NOT_TRUSTED`), then the same two MCUboot lines
as P2, and no `hello from keelsign_hello`.

### P4: classical fallback (NEEDS-HARDWARE)

MCUboot's own signature check stays in force, and a classical-only image does not get
past keelsign:

1. Flash MCUboot and `build/variants/bad-ecdsa.hex` (keelsign's signature valid,
   imgtool's ECDSA signature corrupted), reset. Pass: `I: keelsign: image 0 slot 0
   verified (...)` followed by `E: Image in the primary slot is not valid!` and `E:
   Unable to find bootable image`, with no keelsign reject line: keelsign accepted the
   image and MCUboot's ECDSA check rejected it.
2. Flash MCUboot and `build/keelsign_hello/zephyr/zephyr.signed.hex` (imgtool only, no
   keelsign TLVs), reset. Pass: `E: keelsign: image 0 slot 0 rejected: status 13`
   (`KEELSIGN_ERR_MISSING_PQ_SIGNATURE`), then MCUboot's two lines, no hello.
3. Flash the P1 files again, reset. Pass: P1's output (the board recovers).

## Tests

| What | Where | Needs |
|---|---|---|
| `keelsign_verify_cb` (callback reader) | `keelsign_ffi::abi::tests::verify_cb_*`, `miri_verify_cb_unaligned_reader_struct`, `repo_checks::ffi::c_harness_verify_cb_matches_verify_on_every_fixture` | host |
| Hook verdicts and log lines | `repo_checks::mcuboot::hook_harness_*`, `hook_glue_compiles_against_mcuboot_v2_5_0_rc1_headers` | network (MCUboot clone) |
| Module, manifest, sample, CI job, setup script (text) | `repo_checks::mcuboot::{sysbuild_forces_allow_list_off_and_hooks_on, module_kconfig_refers_to_no_mcuboot_only_symbol, west_manifest_pins_zephyr_v4_4_2, sample_partitions_are_shared_by_both_images, ci_has_the_zephyr_sample_job, zephyr_setup_script_is_pinned_and_guarded, doc_commands_match_scripts}` | host |
| Sample build, classical signature kept, hybrid compile, allow list refused, size table | `repo_checks::mcuboot::zephyr_*` (`cargo test -p repo-checks --locked --test mcuboot -- --ignored zephyr_`), CI job `zephyr-sample` | the workspace of [Setup](#setup) |
| Size table format | `repo_checks::benchmarks_doc::mcuboot_delta_table_is_well_formed` | host |
| P1-P4 | above | hardware |
