# ML-DSA verify benchmarks (SHA-34)

Cycles, peak stack and flash footprint of ML-DSA-44 and ML-DSA-65 signature verification
on the two development boards, and the go/no-go decision for using ML-DSA-44 in
`keelsign-verify`. The verifier under test is RustCrypto `ml-dsa` pinned to `=0.1.1`
(includes the fixes for CVE-2026-24850 / GHSA-5x2r-hc65-25f9 and GHSA-h37v-hp6w-2pp8),
built `no_std` without alloc (`default-features = false`).

| Board | Project | Target | Core clock |
|---|---|---|---|
| nRF52840-DK (Cortex-M4F) | `benches/nrf52840-mldsa` | `thumbv7em-none-eabihf` | 64 MHz |
| Pico 2 W (RP2350, Cortex-M33) | `benches/rp2350-mldsa` | `thumbv8m.main-none-eabihf` | 150 MHz (`embassy_rp::init(Default::default())`) |

## Method

- **Known answers.** `benches/mldsa-kat` holds script-generated fixtures
  (`scripts/gen_mldsa_vectors.py`, pinned sources and sha256 in
  `benches/mldsa-kat/fixtures/MANIFEST.json`):
  - host set: NIST ACVP-Server `v1.1.0.43` ML-DSA-sigVer-FIPS204, external interface,
    pure (15 + 15 cases), plus every Wycheproof `mldsa_{44,65}_verify_test.json` case
    (180 + 210). Run on the host by `cargo test --workspace`.
  - target set (10 cases per parameter set): every ACVP valid case, the first invalid
    ACVP case for each ACVP `reason`, and the Wycheproof advisory regression cases
    (ML-DSA-44 tcId 18, 147, 148; ML-DSA-65 tcId 19, 161, 162). Run on each board by
    `mldsa44_kat` / `mldsa65_kat`.
  - A case "verifies" when the public key and signature have the right length, the
    signature decodes and `VerifyingKey::verify_with_context` (FIPS 204 Algorithm 3,
    pure) returns true. Anything else counts as invalid.
- **Cycles.** The DWT cycle counter (`CYCCNT`) around one call of
  `mldsa_kat::verify_for`, which decodes the public key (including expanding the matrix
  A), decodes the signature and verifies it: the full per-boot cost for a bootloader
  holding the encoded key. Converted to time at the core clock above. Every target case
  is measured and logged with its message length. The headline figure is the
  short-message Wycheproof valid case: tcId 147 (ML-DSA-44) and tcId 161 (ML-DSA-65),
  11-byte message, empty context.
- **Peak stack.** `sp0 = MSP`; `stack_paint::paint` fills the stack from `_stack_end`
  (flip-link puts it at `ORIGIN(RAM)`) up to 256 bytes below the current stack pointer
  with a pattern; verify runs; `stack_paint::high_water(sp0)` finds the lowest
  overwritten word. The measured write watermark is `sp0 - lowest overwritten address`.
  It is reported next to the static reserved frame (see
  [Static stack frame estimate](#static-stack-frame-estimate-provisional)).
- **Flash.** `.text + .rodata + .data` of `size_mldsa44` / `size_mldsa65` minus
  `size_baseline`, per board, for the `release` profile (opt-level 3, fat LTO,
  codegen-units 1, debug 2; the primary column) and the `size` profile (release with
  opt-level `"s"`). All three bins run the HAL init, log one defmt line and black-box a
  reference to both target fixtures, then parse a fixture and find its first valid case
  (the baseline only logs that case's `tc_id`), so the fixture bytes and the parser cancel
  out; the ML-DSA bins add one black-boxed verify of that case. Measured with
  `scripts/elf_sizes.py` (pure Python; no llvm-tools needed).
- **Peak RAM** = measured peak stack + static RAM delta (`.data + .bss + .uninit` of the
  ML-DSA bin minus the baseline; 0 B in every build below, since `ml-dsa` keeps all its
  state on the stack).

## Prerequisites

- The [development setup](setup.md): stable Rust with both thumb targets, probe-rs
  `0.32.0`, flip-link `0.1.12`, and the board wired as in
  [setup.md, Flash and run](setup.md#flash-and-run).
- `python3` (standard library only) for the scripts.
- For the static frame estimate only: a nightly toolchain with the thumb targets
  (measured with `rustc 1.101.0-nightly (c1070d693 2026-09-28)`):

  ```sh
  rustup toolchain install nightly --profile minimal
  rustup target add --toolchain nightly thumbv7em-none-eabihf thumbv8m.main-none-eabihf
  ```

## Reproduce

Every command block below starts from the repository root.

Commands for the nRF52840-DK; for the Pico 2 W use `benches/rp2350-mldsa`, board name
`rp2350` and target `thumbv8m.main-none-eabihf`. The on-target tests refuse to build
without `--release`.

Host KATs and the fixture check (no board):

```sh
cargo test --workspace --locked
python3 scripts/gen_mldsa_vectors.py --check   # needs network: re-downloads and diffs
```

### On-target KATs

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked -- mldsa44_kat
cargo test --release --locked -- mldsa65_kat
cargo test --release --locked -- dwt_cycle_counter_present
```

`probe-rs run` (the runner in `.cargo/config.toml`) detects the embedded-test binary,
flashes it once and runs each selected test after a reset. Each case logs a
`KAT board=… set=… src=… tc=… expect_valid=… verified=… result=ok` line; the test fails
if any case does not match its expectation. `cargo test --release --locked` with no
filter runs all five on-target tests.

### Cycles and peak stack

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked -- _bench 2>&1 | tee ../../docs/bench-logs/nrf52840-run1.txt
```

This runs `mldsa44_bench` and `mldsa65_bench`, which log one line per case:

```text
BENCH board=nrf52840 set=ML-DSA-44 src=wycheproof tc=147 msg_len=11 expect_valid=true ok=true cycles=… us=… peak_stack=… saturated=false
```

Summarise a log into results rows (from the repository root, like every block here):

```sh
python3 scripts/bench_summarize.py docs/bench-logs/nrf52840-run1.txt
```

### Three-run consistency

Run the bench command three times, saving `nrf52840-run1.txt`, `nrf52840-run2.txt` and
`nrf52840-run3.txt` (and `rp2350-run{1,2,3}.txt` for the Pico 2 W) in
`docs/bench-logs/`, then from the repository root:

```sh
python3 scripts/bench_summarize.py --check-consistency 0.05 docs/bench-logs/nrf52840-run1.txt docs/bench-logs/nrf52840-run2.txt docs/bench-logs/nrf52840-run3.txt
python3 scripts/bench_summarize.py --check-consistency 0.05 docs/bench-logs/rp2350-run1.txt docs/bench-logs/rp2350-run2.txt docs/bench-logs/rp2350-run3.txt
cargo test -p repo-checks --locked --test benchmarks_doc -- --ignored three_run_logs_consistent_within_5_percent
```

It passes when every case's `cycles` and `peak_stack` vary by at most 5 % (max / min − 1)
across the three runs. The 5 % rule is applied to cycles as well as to peak stack, which
is stricter than the ticket's wording (peak stack only).

### Flash footprint

```sh
cd benches/nrf52840-mldsa
cargo build --release --locked --bins
cargo build --profile size --locked --bins
python3 ../../scripts/elf_sizes.py --label nrf52840/release --baseline target/thumbv7em-none-eabihf/release/size_baseline target/thumbv7em-none-eabihf/release/size_baseline target/thumbv7em-none-eabihf/release/size_mldsa44 target/thumbv7em-none-eabihf/release/size_mldsa65
python3 ../../scripts/elf_sizes.py --label nrf52840/size --baseline target/thumbv7em-none-eabihf/size/size_baseline target/thumbv7em-none-eabihf/size/size_baseline target/thumbv7em-none-eabihf/size/size_mldsa44 target/thumbv7em-none-eabihf/size/size_mldsa65
```

No board needed. The `Δ flash` column is the figure in [Results](#results).

### Static stack frame estimate

Exact compiled frame sizes (the second condition of the decision rule); nightly only,
not run in CI:

```sh
cd benches/nrf52840-mldsa
cargo +nightly rustc --release --locked --bin size_mldsa44 --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_mldsa44
cargo +nightly rustc --release --locked --bin size_mldsa65 --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_mldsa65
```

`stack_frames.py` prints the largest per-function frames and the frame of
`mldsa_kat::verify_case<…>`.

## Results

Cycles and measured stack need the boards; flash is measured from the cross-built ELFs
(stable Rust 1.91.1). Static frame: the compiled `verify_case` frame, see
[Static stack frame estimate](#static-stack-frame-estimate-provisional).

| Board | Set | Verify cycles (headline) | Verify time | Peak stack (measured) | Static frame (compiled) | Flash Δ release | Flash Δ size | Peak RAM |
|---|---|---|---|---|---|---|---|---|
| nrf52840 | ML-DSA-44 | pending (hardware) | pending (hardware) | pending (hardware) | 93,448 B | 33,756 B | 10,992 B | pending (hardware) |
| nrf52840 | ML-DSA-65 | pending (hardware) | pending (hardware) | pending (hardware) | 153,072 B | 37,496 B | 10,936 B | pending (hardware) |
| rp2350 | ML-DSA-44 | pending (hardware) | pending (hardware) | pending (hardware) | 93,448 B | 33,760 B | 10,988 B | pending (hardware) |
| rp2350 | ML-DSA-65 | pending (hardware) | pending (hardware) | pending (hardware) | 153,072 B | 37,496 B | 10,932 B | pending (hardware) |

Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_baseline` flash | `size_mldsa44` flash | `size_mldsa65` flash | Δ ML-DSA-44 | Δ ML-DSA-65 |
|---|---|---|---|---|---|
| nrf52840 / release | 138,728 | 172,484 | 176,224 | 33,756 | 37,496 |
| nrf52840 / size | 138,148 | 149,140 | 149,084 | 10,992 | 10,936 |
| rp2350 / release | 139,876 | 173,636 | 177,372 | 33,760 | 37,496 |
| rp2350 / size | 138,796 | 149,784 | 149,728 | 10,988 | 10,932 |

The baselines include the two embedded target fixtures (135,414 B of fixture data in
total, placed in `.rodata`) and the fixture parser, which cancel out of the deltas.

## Three-run consistency

Pending (hardware): three saved runs per board in `docs/bench-logs/`, checked with
`bench_summarize.py --check-consistency 0.05` (see [Reproduce](#three-run-consistency)).

## Static stack frame estimate (provisional)

These are exact compiled frame sizes, the second condition of the
[decision rule](#decision); "provisional" in the heading only means that the on-board
watermark, the rule's first condition, is still pending. Per-function frame sizes from
nightly `-Z emit-stack-sizes` (release profile: opt-level 3, fat LTO), read by
`scripts/stack_frames.py`. These are own-frame sizes without a call graph: the
`verify_case` figure is the frame LLVM reserves for verify with everything it inlined
(key decode, matrix A, signature decode, the verify arithmetic); the callees it still
calls add at most a few KB each on top.

| Board | Set | `verify_case` frame | Largest other frame | Stack available (flip-link, test binary) |
|---|---|---|---|---|
| nrf52840 | ML-DSA-44 | 93,448 B | 4,168 B | 261,048 B |
| nrf52840 | ML-DSA-65 | 153,072 B | 4,168 B | 261,048 B |
| rp2350 | ML-DSA-44 | 93,448 B | 4,168 B | 522,960 B |
| rp2350 | ML-DSA-65 | 153,072 B | 4,168 B | 522,960 B |

Both sets fit in the stack available on both boards, so the on-target runs can measure
them. The ML-DSA-44 frame is about 2.9 times the 32 KB limit in the decision rule, which
settles the decision as NO-GO whatever the measured watermark turns out to be.

## pqm4 comparison

C reference numbers from mupq/pqm4 `benchmarks.md` at commit
`90bfb630e53603b4e273a131cd09a025e51540a5` (NUCLEO-L4R5ZI, Cortex-M4F; verify, average
of 1000 executions; stack in bytes; `.text` in bytes):

| Scheme | Implementation | Verify cycles | Verify stack | `.text` |
|---|---|---|---|---|
| ml-dsa-44 | clean | 2,063,096 | 36,308 | 8,212 |
| ml-dsa-44 | m4f | 1,421,623 | 8,912 | 19,592 |
| ml-dsa-44 | m4fstack | 3,242,333 | 2,712 | 24,844 |
| ml-dsa-65 | clean | 3,377,305 | 57,736 | 7,724 |
| ml-dsa-65 | m4f | 2,415,944 | 9,888 | 19,328 |
| ml-dsa-65 | m4fstack | 5,732,397 | 2,712 | 24,120 |

pqm4's verify takes the encoded public key and signature, like `mldsa_kat::verify_case`
here. The nRF52840 has the same Cortex-M4F core, so its cycle counts are the closest
comparison (pqm4 clocks its board for zero flash wait states; the nRF52840 runs from
flash through its cache at 64 MHz). The RP2350 is a Cortex-M33.

## Decision

Rule: ML-DSA-44 verify is GO for `keelsign-verify` only if both the measured write
watermark (Peak stack, measured, on both boards) and the static reserved frame are
≤ 32 KB (32,768 B). Otherwise it is NO-GO, and a NO-GO links SHA-170 (re-plan
LMS-first).

Decision: NO-GO — [SHA-170](https://linear.app/shakooky/issue/SHA-170) re-plans keelsign LMS-first; the path back to ML-DSA is [SHA-169](https://linear.app/shakooky/issue/SHA-169) (low-stack ML-DSA verify).

Why now, before the board runs: the rule needs both conditions, and the second one
already fails. The compiled `verify_case<MlDsa44>` frame is 93,448 B, about 2.9 times the
32,768 B limit. That is the exact stack the function reserves in the documented nightly
build (see [Static stack frame estimate](#static-stack-frame-estimate-provisional)), not
an estimate that a board measurement could revise, so no measured watermark can change
the outcome. The frame was taken with the documented nightly compiler; the stable build's
frame may differ slightly, but not by anything close to that 2.9× margin.

The board runs still fill in the cycles and the measured peak stack in
[Results](#results) for the record (the `pending (hardware)` cells).

## Follow-ups

Filed in Linear (project keelsign):

- **[SHA-169](https://linear.app/shakooky/issue/SHA-169)**: low-stack ML-DSA verify (an upstream issue against RustCrypto `ml-dsa`, or
  an alternative implementation).
- **[SHA-170](https://linear.app/shakooky/issue/SHA-170)**: re-plan keelsign LMS-first
  (the decision above is NO-GO).

## LMS/HSS verify (SHA-65)

After the NO-GO above, keelsign verifies LMS/HSS first. `keelsign_verify::lms` is an
in-house verifier of HSS signatures (RFC 8554 §4.6 Algorithm 4b, §5.4.2 Algorithm 6/6a,
§6.3) over SHA-256 and SHA-256/192 (SP 800-208 §2.3, the leftmost 24 bytes of SHA-256),
built on the `sha2 =0.11.0` dependency `keelsign-verify` already has for key IDs. It runs
without heap, panics or slice indexing. The device path,
`keelsign_verify::verify_pq` with `DefaultBackend::new()`, applies the device default
`ParameterPolicy::keelsign_default()`: LMS_SHA256_M32_H{5..25} (0x05–0x09) with
LMOTS_SHA256_N32_W8 (0x04), or LMS_SHA256_M24_H{5..25} (0x0A–0x0E) with
LMOTS_SHA256_N24_W8 (0x08), at most 2 HSS levels, the same hash at every level. Two
levels deviate from CNSA 2.0, which allows single-tree LMS only; the strict
`ParameterPolicy::cnsa_2_0()` (same pairs, `L = 1` only, SHA-240) is selected with
`verify_pq_with(&DefaultBackend::cnsa_2_0(), ..)` (docs/image-format.md, "Accepted LMS
parameter sets and CNSA 2.0"). The policy is checked for every level before anything is
hashed; anything outside it is `Error::UnsupportedParameterSet`.
`ParameterPolicy::rfc_8554_all_sets()` (every SHA-256 / SHA-256/192 set, W1–W8, up to
8 levels) exists only for the host tests against published vectors outside the device
policies; no device path reaches it.

### Crate choice

Measured on `thumbv7em-none-eabihf` during planning (hbs-lms, lms-signature) and
re-measured for the in-house verifier from `size_lms` below:

| | hbs-lms 0.1.1 | lms-signature 0.1.0-rc.2 | in-house (`keelsign_verify::lms`) |
|---|---|---|---|
| `no_std` verify | yes | no (std only) | yes |
| SHA-256/192 | wrong typecodes (upstream issue #100) | no; no HSS either | yes |
| ACVP M24 vectors | panics (`unwrap`, `signing.rs:174`) | n/a | pass (16 of 16) |
| Extra dependencies | a second sha2/digest, sha3, tinyvec, zeroize | getrandom, rand_core, … | none |
| Flash Δ, release / size | +15,116 / +8,056 B (raw verify) | — | +7,224 / +5,348 B (whole `verify_pq` path) |
| Static frame | 17,544 B | — | 1,488 B call chain |
| Lines to audit | 5,064 | 2,553 | ≈ 410 (`lms.rs` code, without comments and tests) |
| Licence | Apache-2.0 only | MIT OR Apache-2.0 | MIT OR Apache-2.0 |

Choice: in-house (`keelsign_verify::lms`), approved by the user on 2026-09-29.

Justification (E8.2): no new dependency; sha2 =0.11.0 already pinned. The in-house
verifier is the only candidate that is `no_std`, supports SHA-256/192 with the IANA
typecodes, passes the ACVP SHA-256/192 vectors and HSS, and it is small enough to audit
line by line against RFC 8554.

The in-house flash delta covers more than the hbs-lms figure: it is `verify_pq` with
TLV selection, dispatch and the LMS/HSS backend, measured against a baseline that already
links SHA-256 (for key IDs) and the fixture parser.

### Known-answer evidence

`benches/lms-kat` holds script-generated fixtures (`scripts/gen_lms_vectors.py`; pinned
sources and sha256 in `benches/lms-kat/fixtures/MANIFEST.json`; format KSLM v2). Each case
carries three expectations: `verify_pq` (`keelsign_default()`, L ≤ 2), the strict device
path `verify_pq_with(&DefaultBackend::cnsa_2_0(), ..)` (`cnsa_2_0()`: every `L ≠ 1` key is
`UnsupportedParameterSet` before the signature is read, so the script derives this column
as the default expectation for `L = 1` keys and `UnsupportedParameterSet` otherwise) and
the RFC policy. The results below are for `verify_pq`:

- RFC 8554 Appendix F Test Case 1 (HSS L=2, both levels M32_H5/W8): verifies through
  `verify_pq`. Test Case 2 (top level M32_H10/W4): `UnsupportedParameterSet` through
  `verify_pq`, verifies under `rfc_8554_all_sets`.
- NIST ACVP-Server `975de31` LMS sigVer, revisions SP800-208 and 1.0: all 16 cases
  (LMS_SHA256_M24_H5 with LMOTS_SHA256_N24_W1, LMS_SHA256_M24_H10 with
  LMOTS_SHA256_N24_W2; 4 valid, 12 invalid) match under `rfc_8554_all_sets` and are
  `UnsupportedParameterSet` through `verify_pq`.
- Signed by the pinned independent signer `hsslms 0.1.3` (PyPI sdist, sha256-checked,
  vendored at run time, deterministic DRBG): M32/W8 H5, H5+H5, H10, H5+H10; M24/W8 H5,
  H5+H5, H10; rotation keys A and B; and W4, W2 and L=3 outside the policy.
- Negatives derived from Test Case 1: flipped last byte, C and both q values
  (`SignatureInvalid`), 28 truncations and a trailing byte (`MalformedSignature`), the key
  patched to L=3 (`UnsupportedParameterSet`).
- Negatives derived from hsslms M32/W8 H5+H5: the bottom-level q set to exactly 2^h
  (RFC 8554 Algorithm 6a step 2i), and only the bottom-level LM-OTS typecode inside the
  signature changed from N32_W8 to N24_W8 (step 2c; every length still follows from the
  public key and the gate covers public keys only, so only the typecode check rejects
  it). Both are `SignatureInvalid` under the default and RFC policies.

AC1 evidence note: accepted-set SHA-256/192 and HSS-2/W8 coverage comes from RFC 8554
Test Case 1 plus the fixtures signed by the pinned independent `hsslms 0.1.3`. No NIST
vectors exist for those sets (the ACVP LMS vectors are single-tree SHA-256/192 with W1
and W2 only). Heights H15 and above are accepted but covered by the parameter-table
tests only; no fixture is signed above H10.

The host set (`lms-host.bin`, 66 cases) runs in `cargo test --workspace`; the on-target
set (`lms-target.bin`, 14 cases: TC1, TC2, ACVP SP800-208 tc 6, hsslms M32 H5+H5,
M24 H5 and H5+H5, rotation A and B, W4, L=3, the flipped last byte, the trailing
byte, q = 2^h and the LM-OTS typecode mismatch) runs on each board in `lms_kat`, which
checks all three expectations of every case (the strict one through
`DefaultBackend::cnsa_2_0()`, in the same binary; there is no separate strict build) and
the key-rotation pair. Under `cnsa_2_0()` the target set holds single trees that verify
(M24 H5, rotation A and B) and valid two-level cases that are refused (TC1, M32 H5+H5,
M24 H5+H5).

### LMS method

Same as for ML-DSA (see [Method](#method)), with these differences:

- **Cycles and peak stack**: `lms_bench` measures one `lms_kat::verify_case` per target
  case: a trusted-key set holding the case's key (one SHA-256 over the 52- or 60-byte
  key) and `verify_pq` over the image TLVs, message and signature. It logs
  `BENCH board=… set=LMS-<M>_<H>-<W>-L<levels> src=… tc=… msg_len=… sig_len=… …` and
  fails if a case misses its expectation, saturates the painted stack or uses more than
  32,768 B of stack. The headline per set is the shortest-message valid case
  (`bench_summarize.py`).
- **Flash**: `size_lms` minus `size_lms_baseline`. Both parse the LMS target fixture,
  find its first case the default policy accepts and build a trusted-key set for it (so SHA-256
  and the parser cancel out); `size_lms` adds one black-boxed `verify_pq`.
- **Static frame**: nightly `-Z emit-stack-sizes` own-frame sizes of `size_lms`, summed
  along the deepest call chain below `lms_kat::verify_with_keys`: `verify_with_keys`
  72 + `DefaultBackend::verify` 88 + `lms::walk` 144 + `lms::lms_verify` 648 (Algorithm
  4b inlined) + `lms::hash` 256 + `finalize_fixed_core` 104 + `sha2::sha256::compress256`
  176 = 1,488 B, identical on both boards. There is no recursion and no call through a
  function pointer on this path.

### LMS results

Cycles and measured stack need the boards; flash, static frame and signature sizes are
measured without them (stable Rust 1.91.1, nightly `rustc 1.101.0-nightly (c1070d693
2026-09-28)` for the frames). One verifier serves both hash sizes, so the flash and frame
columns are the same for both sets.

| Board | Set | Verify cycles (headline) | Verify time | Peak stack (measured) | Static frame (compiled) | Flash Δ release | Flash Δ size | LMS signature (H10) | HSS signature (H10+H10, L=2) |
|---|---|---|---|---|---|---|---|---|---|
| nrf52840 | LMS SHA-256 M32/W8 | pending (hardware) | pending (hardware) | pending (hardware) | 1,488 B | 7,224 B | 5,348 B | 1,452 B | 2,964 B |
| nrf52840 | LMS SHA-256/192 M24/W8 | pending (hardware) | pending (hardware) | pending (hardware) | 1,488 B | 7,224 B | 5,348 B | 900 B | 1,852 B |
| rp2350 | LMS SHA-256 M32/W8 | pending (hardware) | pending (hardware) | pending (hardware) | 1,488 B | 7,228 B | 5,340 B | 1,452 B | 2,964 B |
| rp2350 | LMS SHA-256/192 M24/W8 | pending (hardware) | pending (hardware) | pending (hardware) | 1,488 B | 7,228 B | 5,340 B | 900 B | 1,852 B |

An LMS signature is `4 + (4 + n * (p + 1)) + 4 + m * h` bytes (RFC 8554 §5.4) with
p = 34 (N32/W8) or 26 (N24/W8); an HSS signature with L levels is
`4 + L * LMS signature + (L - 1) * (24 + m)` (so an L=1 image carries 1,456 B for M32 H10
and 904 B for M24 H10). At H20 the LMS / HSS-2 (H20+H20) sizes are 1,772 / 3,604 B (M32)
and 1,140 / 2,332 B (M24). Public keys are 60 B (M32) and 52 B (M24). The hsslms
fixtures confirm the H5 and H10 sizes (`lms_kat::host_kat::hsslms_signed_w8_cases_verify_under_keelsign_default`).

Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_lms_baseline` flash | `size_lms` flash | Δ LMS/HSS |
|---|---|---|---|
| nrf52840 / release | 47,272 | 54,496 | 7,224 |
| nrf52840 / size | 47,260 | 52,608 | 5,348 |
| rp2350 / release | 48,412 | 55,640 | 7,228 |
| rp2350 / size | 47,908 | 53,248 | 5,340 |

Both baselines include the 35,659-byte LMS target fixture (KSLM v2) in `.rodata`.
Re-measured for SHA-240. At `2152d0c`, just before SHA-240, the same commands gave
Δ 7,180 / 5,328 B (nrf52840 release / size) and 7,192 / 5,332 B (rp2350); the older
6,740 / 5,136 and 6,756 / 5,144 B figures had drifted since SHA-65. SHA-240 itself adds
the policy field read in `DefaultBackend::verify` and the third expectation byte (+14 B
of fixture per baseline).

The stack limit (AC4) is 32,768 B measured on both boards; the compiled call chain is
1,488 B, so the limit holds with a wide margin unless the board measurement shows
otherwise.

### LMS reproduce

Every command block starts from the repository root. For the Pico 2 W use
`benches/rp2350-mldsa`, board `rp2350` and target `thumbv8m.main-none-eabihf`.

Host KATs and the fixture check (no board):

```sh
cargo test --workspace --locked
python3 scripts/gen_lms_vectors.py --check   # needs network: re-downloads and diffs
```

On-target KATs, rotation and benchmark (manual procedure, needs the board):

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked --test lms -- lms_kat
cargo test --release --locked --test lms -- lms_rotation_key_b_verifies_against_a_b_and_fails_against_a
cargo test --release --locked --test lms -- lms_bench 2>&1 | tee ../../docs/bench-logs/nrf52840-lms-run1.txt
```

`lms_kat` logs `KAT board=… set=LMS src=… tc=… expect_default=… default=… expect_cnsa2=…
cnsa2=… expect_rfc=… rfc=… result=ok` per case and `ROTATION board=… … ok`; summarise the bench log with
`python3 scripts/bench_summarize.py docs/bench-logs/nrf52840-lms-run1.txt` and record
the headline cycles, time and peak stack in [LMS results](#lms-results). The SHA-34
filter `-- _bench` now also runs `lms_bench`.

Flash footprint (no board):

```sh
cd benches/nrf52840-mldsa
cargo build --release --locked --bins
cargo build --profile size --locked --bins
python3 ../../scripts/elf_sizes.py --label nrf52840/release --baseline target/thumbv7em-none-eabihf/release/size_lms_baseline target/thumbv7em-none-eabihf/release/size_lms_baseline target/thumbv7em-none-eabihf/release/size_lms
python3 ../../scripts/elf_sizes.py --label nrf52840/size --baseline target/thumbv7em-none-eabihf/size/size_lms_baseline target/thumbv7em-none-eabihf/size/size_lms_baseline target/thumbv7em-none-eabihf/size/size_lms
```

Static frames (nightly only, not run in CI):

```sh
cd benches/nrf52840-mldsa
cargo +nightly rustc --release --locked --bin size_lms --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_lms --top 12 --match keelsign_verify
```

## Image digest (SHA-42)

`keelsign_verify::image_digest` computes the image digest `M` (SHA-256 of the header,
the body and the protected TLV area, the value of the `SHA256` TLV) from an
`ImageReader`: it hashes the 32 header bytes kept by `Image` (never re-read from the
slot), then streams the rest of `Image::hashed_range` through the caller's chunk buffer.
`Image::read_from` reads the header and the TLV areas (sized from their info headers,
after checking that they fit `ImageReader::len`) into a caller buffer.
`NorFlashReader` adapts any `embedded-storage` `ReadNorFlash` with `READ_SIZE == 1`
(the nRF52840 NVMC and the RP2350 blocking flash driver) to `ImageReader`, with
slot-relative offsets.

### Digest method

- **RAM bound**: peak RAM of one digest is `chunk.len()` + the SHA-256 state (about
  108 B: 32 B chaining value, 64 B block buffer, block count and buffer position) + the
  frame of `image_digest`. Nothing scales with the image. The default chunk is
  `DEFAULT_CHUNK_LEN` = 256 B, MCUboot's `BOOT_TMPBUF_SZ` (`bootutil_priv.h:86` at
  `a8ffd2c`). With it, the compiled bound is 256 + 512 = 768 B (static frames below).
- **Static frame**: nightly `-Z emit-stack-sizes` own-frame sizes of `size_digest`, in
  which `image_digest` and `Image::read_from` each sit alone in an `#[inline(never)]`
  wrapper: `size_digest::digest<NorFlashReader<…>>` 336 B (`image_digest` with the
  SHA-256 state, the reader and `finalize` inlined) + `sha2::sha256::compress256` 176 B
  = 512 B, identical on both boards. `Image::read_from`: `size_digest::read_image<…>`
  232 B + `Image::parse_parts` 48 B = 280 B. The chunk (256 B) and the TLV buffer
  (4 KiB) are the caller's and not in these figures.
- **Flash**: `size_digest` minus `size_digest_baseline`. The baseline is HAL init, the
  flash driver, defmt and a black-boxed reference to the 2,315-byte golden image
  `mcuboot-ed25519.bin` in `.rodata`; `size_digest` adds `NorFlashReader`,
  `Image::read_from` (the image parser), `image_digest` and SHA-256 (sha2 `=0.11.0`,
  `compress256` in software), run once over that image.
- **On target** (`tests/image.rs`, needs the board): the "DFU slot" is the 200 KB golden
  image `mcuboot-ed25519-200k.bin` (204,800-byte body, 205,579 B) embedded in the test
  binary's `.rodata` and read back through the HAL's `ReadNorFlash` at its flash offset
  (nRF52840: the address; RP2350: the address minus the XIP base `0x1000_0000`). A fixed
  partition address would need `#[link_section]`, an unsafe attribute in edition 2024;
  the real DFU partition comes with the embassy-boot adapter (SHA-55).
  `image_digest_200k_from_flash` runs `Image::read_from` (4 KiB TLV buffer) and
  `image_digest` with a 256 B chunk, and checks the digest against the `SHA256` TLV, the
  in-memory `&[u8]` reader and 64 B and 4096 B chunks, logging the digest.
  `image_digest_bench` paints the stack and times one 256 B-chunk digest with `CYCCNT`
  (the chunk on the measured frame), logs
  `DIGEST board=… bytes=204800 chunk=256 cycles=… us=… peak_stack=… saturated=false` and
  fails if the stack saturates or the peak exceeds 4,096 B.

### Digest results

Cycles and measured stack need the boards; flash and static frames are measured without
them (stable Rust 1.91.1, nightly `rustc 1.101.0-nightly (c1070d693 2026-09-28)` for the
frames).

| Board | Digest cycles (200 KB, 256 B chunk) | Digest time | Peak stack (measured) | Static frame (compiled) | Peak RAM bound (256 B chunk) | Flash Δ release | Flash Δ size |
|---|---|---|---|---|---|---|---|
| nrf52840 | pending (hardware) | pending (hardware) | pending (hardware) | 512 B | 768 B | 10,200 B | 9,964 B |
| rp2350 | pending (hardware) | pending (hardware) | pending (hardware) | 512 B | 768 B | 10,240 B | 10,004 B |

Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_digest_baseline` flash | `size_digest` flash | Δ digest |
|---|---|---|---|
| nrf52840 / release | 5,192 | 15,392 | 10,200 |
| nrf52840 / size | 4,604 | 14,568 | 9,964 |
| rp2350 / release | 6,392 | 16,632 | 10,240 |
| rp2350 / size | 5,308 | 15,312 | 10,004 |

Both baselines include the 2,315-byte image in `.rodata`. The on-target stack limit is
4,096 B; the compiled bound with a 256 B chunk is 768 B.

### Digest reproduce

Every command block starts from the repository root. For the Pico 2 W use
`benches/rp2350-mldsa`, board `rp2350` and target `thumbv8m.main-none-eabihf`.

Host tests (no board):

```sh
cargo test -p keelsign-verify --locked
```

On-target digest and benchmark (manual procedure, needs the board):

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked --test image -- image_digest_200k_from_flash
cargo test --release --locked --test image -- image_digest_bench 2>&1 | tee ../../docs/bench-logs/nrf52840-digest-run1.txt
```

`image_digest_200k_from_flash` logs `DIGEST_HEX board=… digest=…` (compare with
`digest_hex` of `mcuboot-ed25519-200k.bin` in `tests/fixtures/images/MANIFEST.json`) and
`DIGEST board=… from_flash=ok sha256_tlv=ok chunks=64,256,4096 ok`; record the cycles,
time and peak stack of the `image_digest_bench` line in [Digest results](#digest-results).

Flash footprint (no board):

```sh
cd benches/nrf52840-mldsa
cargo build --release --locked --bins
cargo build --profile size --locked --bins
python3 ../../scripts/elf_sizes.py --label nrf52840/release --baseline target/thumbv7em-none-eabihf/release/size_digest_baseline target/thumbv7em-none-eabihf/release/size_digest_baseline target/thumbv7em-none-eabihf/release/size_digest
python3 ../../scripts/elf_sizes.py --label nrf52840/size --baseline target/thumbv7em-none-eabihf/size/size_digest_baseline target/thumbv7em-none-eabihf/size/size_digest_baseline target/thumbv7em-none-eabihf/size/size_digest
```

Static frames (nightly only, not run in CI):

```sh
cd benches/nrf52840-mldsa
cargo +nightly rustc --release --locked --bin size_digest --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_digest --top 8 --match size_digest::
```
