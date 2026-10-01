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

SHA-44 put ML-DSA verify into `keelsign-verify` behind the off-by-default `ml-dsa` feature
anyway, with this decision unchanged: its stack is recorded in
[ML-DSA verify (SHA-44)](#ml-dsa-verify-sha-44).

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
slot), streams the body (offsets 32 up to the TLV offset) through the caller's chunk
buffer, and hashes the protected TLV area from the parsed copy (SHA-46: never re-read
either, so the security counter `verify` reports is what was hashed).
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
  `a8ffd2c`). With it, the compiled bound is 256 + 520 = 776 B (static frames below).
- **Static frame**: nightly `-Z emit-stack-sizes` own-frame sizes of `size_digest`, in
  which `image_digest` and `Image::read_from` each sit alone in an `#[inline(never)]`
  wrapper: `size_digest::digest<NorFlashReader<…>>` 344 B (`image_digest` with the
  SHA-256 state, the reader and `finalize` inlined) + `sha2::sha256::compress256` 176 B
  = 520 B, identical on both boards. `Image::read_from`: `size_digest::read_image<…>`
  248 B + `Image::parse_parts` 64 B = 312 B (re-measured for SHA-46: `image_digest` now
  hashes the protected area from the parsed copy and `TlvArea` keeps the whole area). The chunk (256 B) and the TLV buffer
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
| nrf52840 | pending (hardware) | pending (hardware) | pending (hardware) | 520 B | 776 B | 10,368 B | 10,168 B |
| rp2350 | pending (hardware) | pending (hardware) | pending (hardware) | 520 B | 776 B | 10,400 B | 10,204 B |

Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_digest_baseline` flash | `size_digest` flash | Δ digest |
|---|---|---|---|
| nrf52840 / release | 5,192 | 15,560 | 10,368 |
| nrf52840 / size | 4,604 | 14,772 | 10,168 |
| rp2350 / release | 6,392 | 16,792 | 10,400 |
| rp2350 / size | 5,308 | 15,512 | 10,204 |

Both baselines include the 2,315-byte image in `.rodata`. The on-target stack limit is
4,096 B; the compiled bound with a 256 B chunk is 776 B. Re-measured for SHA-46 (the
SHA-42 figures were 10,200 / 9,964 / 10,240 / 10,004 B): hashing the protected TLV area
from the parsed copy costs 160–204 B.

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

## Hybrid verify entry point (SHA-46)

`keelsign_verify::verify` under `Policy::Hybrid` is what a hybrid bootloader runs: the
image rules, `Image::read_from`, `image_digest` (which since SHA-46 streams only the body
and hashes the header and the protected TLV area from the parsed copy), the Ed25519 half
(`ed25519-dalek` `=3.0.0`, `verify_strict`, the `ed25519` feature) and the LMS/HSS half.
The policies and the matrix are specified in [docs/policy.md](policy.md).

### Hybrid method

- **Flash**: `size_verify` minus `size_verify_baseline`. The baseline is HAL init, the
  flash driver, defmt and black-boxed references to the hybrid image
  `keelsign-hybrid-ed25519-lms.bin` (3,512 B), its LMS public key (found in
  `policy-matrix.bin`, which both bins parse) and the Ed25519 test key; `size_verify`
  adds one `verify(.., Policy::Hybrid, ..)` of that image through `NorFlashReader`
  (4 KiB TLV buffer, 256 B chunk). The delta is `verify` with everything it pulls in:
  the image rules, the parser, the digest with SHA-256, Ed25519 (curve25519 field and
  point arithmetic on the u32 serial backend, SHA-512) and the LMS/HSS verifier.
- **Static frame**: nightly `-Z emit-stack-sizes` own-frame sizes of `size_verify`, in
  which `verify` sits in an `#[inline(never)]` wrapper (`size_verify::verify_hybrid`)
  together with the 4 KiB TLV buffer and the 256 B chunk. The deepest chain is the
  Ed25519 half: `size_verify::verify_hybrid` 4,896 B (`verify_with`, `read_from` and the
  digest inlined, the two buffers included) + `keelsign_verify::ed25519::verify_signature`
  4,912 B (the NAF lookup tables) + `NafLookupTable5::from` 2,096 B +
  `FieldElement2625::pow22501` 848 B ≈ 12.8 KB, identical on both boards; the LMS half
  adds `lms_verify` 640 B + `lms::hash` 256 B + `compress256` 176 B to the wrapper. These
  are own-frame sizes without a call graph, so the chain is an estimate, far under the
  32,768 B limit of the LMS tests.
- **On target** (`tests/policy.rs`, needs the board): `policy_matrix_from_flash` runs
  every case of `policy-matrix.bin` (52 images since SHA-44, every one in
  `tests/fixtures/images/` but the 200 KB image) under every policy through `policy_kat::run_fixture`, each image read
  through `NorFlashReader` over `&mut` the board flash at its `.rodata` address (nRF52840:
  the address; RP2350: the address minus the XIP base `0x1000_0000`), with
  `DefaultBackend::new()`, a 4 KiB TLV buffer and a 256 B chunk. It logs
  `POLICY board=… case=… policy=… expect=… got=… result=ok` for each of the 156 cells and
  `POLICY board=nrf52840 passed=156/156` (or `board=rp2350`), and fails on any mismatch.
  With the bench `ml-dsa` feature the ML-DSA cells verify; without it they expect the
  `ml-dsa`-off verdicts (`policy-matrix.bin` KSPM v2 carries both), so both builds give
  `passed=156/156`.

### Hybrid results

Cycles and the measured peak stack of a hybrid verify are SHA-69; flash and static frames
are measured without the boards (stable Rust 1.91.1, nightly
`rustc 1.101.0-nightly (c1070d693 2026-09-28)` for the frames).

| Board | Flash Δ release | Flash Δ size | Static frame (compiled, deepest chain) | Cycles | Peak stack |
|---|---|---|---|---|---|
| nrf52840 | 74,376 B | 59,144 B | 12,752 B | pending (SHA-69) | pending (SHA-69) |
| rp2350 | 74,264 B | 59,152 B | 12,752 B | pending (SHA-69) | pending (SHA-69) |

Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_verify_baseline` flash | `size_verify` flash | Δ verify |
|---|---|---|---|
| nrf52840 / release | 14,940 | 89,316 | 74,376 |
| nrf52840 / size | 14,132 | 73,276 | 59,144 |
| rp2350 / release | 16,092 | 90,356 | 74,264 |
| rp2350 / size | 14,772 | 73,924 | 59,152 |

Both baselines include the 3,512-byte image and the 7,295-byte `policy-matrix.bin` in
`.rodata`. The delta is roughly the digest (about 10.4 KB, above), the LMS/HSS verifier
(see [LMS results](#lms-results)) and Ed25519, which the planning measurement put at
43 KB (`opt-level = "s"`) to 57 KB (`opt-level = 3`) on its own. A `PqOnly` build
without the `ed25519` feature carries none of the Ed25519 code.

### Hybrid reproduce

Every command block starts from the repository root. For the Pico 2 W use
`benches/rp2350-mldsa`, board `rp2350` and target `thumbv8m.main-none-eabihf`.

Host tests (no board):

```sh
cargo test -p keelsign-verify --locked --features ed25519 --test policy_matrix
cargo test -p policy-kat --locked
```

On-target policy matrix (manual procedure, needs the board):

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked --test policy -- policy_matrix_from_flash
```

Expect `POLICY board=nrf52840 passed=156/156` and no `result=FAIL` line, with and without
`--features ml-dsa`.

Flash footprint (no board):

```sh
cd benches/nrf52840-mldsa
cargo build --release --locked --bins
cargo build --profile size --locked --bins
python3 ../../scripts/elf_sizes.py --label nrf52840/release --baseline target/thumbv7em-none-eabihf/release/size_verify_baseline target/thumbv7em-none-eabihf/release/size_verify_baseline target/thumbv7em-none-eabihf/release/size_verify
python3 ../../scripts/elf_sizes.py --label nrf52840/size --baseline target/thumbv7em-none-eabihf/size/size_verify_baseline target/thumbv7em-none-eabihf/size/size_verify_baseline target/thumbv7em-none-eabihf/size/size_verify
```

Static frames (nightly only, not run in CI):

```sh
cd benches/nrf52840-mldsa
cargo +nightly rustc --release --locked --bin size_verify --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_verify --top 16
```

## ML-DSA verify (SHA-44)

`keelsign-verify` verifies ML-DSA-44/65 behind its off-by-default `ml-dsa` feature
(`keelsign_verify::mldsa`: pure FIPS 204 `ML-DSA.Verify` over `M` with `MLDSA_CONTEXT`,
through `ml-dsa` `=0.1.1` without default features, so no heap). This section records
what enabling the feature costs on the two boards. The SHA-34 [Decision](#decision)
stands: the stack is far over the 32 KB device budget, and
[SHA-169](https://linear.app/shakooky/issue/SHA-169) owns a low-stack verify.

### ML-DSA verify method

- **Bench feature**: both bench projects have a Cargo feature `ml-dsa =
  ["keelsign-verify/ml-dsa"]`, off by default, built into its own target dir
  (`--target-dir target/mldsa`). Without it every other test, bin and recorded number in
  this document is built exactly as before.
- **Static frame**: nightly `-Z emit-stack-sizes` own-frame sizes of `size_verify` built
  `--features ml-dsa` (its `verify` then contains the ML-DSA arms), read by
  `scripts/stack_frames.py`. Each parameter set verifies in its own
  `#[inline(never)]` frame, `keelsign_verify::mldsa::verify_param<P>`, so the
  `verify_with` chain (`size_verify::verify_hybrid`, with the 4 KiB TLV buffer and the
  256 B chunk) stays within 8 B of its feature-off size and an LMS/HSS or Ed25519 verify does not
  reserve the ML-DSA stack. (Inlined, the planning measurement put the merged dispatcher
  frame at 156,448 B for every verify.)
- **Flash Δ**: `size_verify` built `--features ml-dsa` minus the same bin without it
  (`elf_sizes.py --baseline`): the ML-DSA verifier and everything it pulls in.
- **On target** (`tests/mldsa_verify.rs`, needs the board and `--features ml-dsa`):
  `mldsa_images_from_flash` verifies the five valid ML-DSA images of the policy matrix
  (`keelsign-mldsa44.bin`, `keelsign-mldsa65.bin`, both `-protected-tlvs` variants under
  `Policy::PqOnly`, `keelsign-hybrid-ed25519-mldsa44.bin` under `Policy::Hybrid`), each read
  through `NorFlashReader` at its `.rodata` address with the keys from `policy-matrix.bin`,
  a 4 KiB TLV buffer and a 256 B chunk on the measured frame. Each verify runs between
  `stack_paint::paint` and `stack_paint::high_water` and is timed with `CYCCNT`; the test
  logs `MLDSA board=… image=… set=… policy=… result=Ok cycles=… us=… peak_stack=…
  saturated=false` per image and `MLDSA board=nrf52840 passed=5/5` (or `board=rp2350`).
  It fails on any verdict other than `Ok` or a saturated paint; it does not assert the
  32 KB budget, whose breach is the documented finding, not a test failure.

### Stack the feature needs

**`ml-dsa` needs 93,456 B (ML-DSA-44) / 153,080 B (ML-DSA-65) of stack for the
`mldsa::verify_param` frame alone (release; 73,872 / 118,952 B at `opt-level = "s"`), on
top of the `verify_with` chain (about 4.9 KB with the buffers, plus a few KB of ML-DSA
callees).** That is far over the 32 KB (32,768 B) on-device budget of the SHA-34 decision
rule. Both sets fit in the stack the test binaries have (261,048 B on the nRF52840,
522,960 B on the RP2350; ML-DSA-65 leaves about 85 KB free on the nRF52840), so the board
runs can measure them, but a real 256 KB-RAM bootloader cannot spare 153 KB beside its
application. Integrators who enable `ml-dsa` on a device must budget that stack
themselves until [SHA-169](https://linear.app/shakooky/issue/SHA-169) lands.

### ML-DSA verify results

Static frames and flash are measured without the boards (stable Rust 1.91.1, nightly
`rustc 1.101.0-nightly (c1070d693 2026-09-28)` for the frames); peak stack and cycles need
the boards (`tests/mldsa_verify.rs`).

| Board | Set | Static frame release | Static frame size | `verify_with` frame (ml-dsa on / off, release) | Flash Δ ml-dsa (release / size) | Peak stack (measured) | Cycles |
|---|---|---|---|---|---|---|---|
| nrf52840 | ML-DSA-44 | 93,456 B | 73,872 B | 4,912 B / 4,904 B | 55,232 B / 13,832 B | pending (hardware) | pending (hardware) |
| nrf52840 | ML-DSA-65 | 153,080 B | 118,952 B | 4,912 B / 4,904 B | 55,232 B / 13,832 B | pending (hardware) | pending (hardware) |
| rp2350 | ML-DSA-44 | 93,456 B | 73,872 B | 4,912 B / 4,904 B | 55,176 B / 13,828 B | pending (hardware) | pending (hardware) |
| rp2350 | ML-DSA-65 | 153,080 B | 118,952 B | 4,912 B / 4,904 B | 55,176 B / 13,828 B | pending (hardware) | pending (hardware) |

The frames are identical on both boards and match SHA-34's `verify_case` (93,448 /
153,072 B) within 8 B. The flash Δ is one figure for both sets: one `size_verify` carries
both arms. Flash detail (`elf_sizes.py`, bytes; static RAM delta is 0 in every row):

| Board / profile | `size_verify` flash (ml-dsa off) | `size_verify` flash (ml-dsa on) | Δ ml-dsa |
|---|---|---|---|
| nrf52840 / release | 120,108 | 175,340 | 55,232 |
| nrf52840 / size | 103,952 | 117,784 | 13,832 |
| rp2350 / release | 121,188 | 176,364 | 55,176 |
| rp2350 / size | 104,604 | 118,432 | 13,828 |

Feature-off drift. The `size_verify` (ml-dsa off) figures include the KSPM v2
`policy-matrix.bin` (37,633 B, up from 7,295 B: 19 more images and the off-cells) in
`.rodata`, which `size_verify_baseline` carries too, so it cancels out of the SHA-46
delta. With the feature off, SHA-44 still changes `keelsign-verify` itself
(the `DefaultBackend` ML-DSA arm with its `cnsa_2_0()` refusal) and `policy-kat` (six
codes per case): re-measured with the same commands, the SHA-46 hybrid delta is
74,736 / 59,380 B (nrf52840 release / size) and 74,656 / 59,372 B (rp2350), against
74,376 / 59,144 and 74,264 / 59,152 B at `861abce` (the SHA-46 tip), and the
`verify_hybrid` frame 4,904 B against 4,896 B. The LMS/HSS delta is 7,216 / 5,384 B
(nrf52840) and 7,224 / 5,384 B (rp2350), against 6,836 / 5,236 and 6,844 / 5,236 B at
`861abce` (the [LMS results](#lms-results) table still shows the SHA-240 figures). The
digest and the SHA-34 ML-DSA bins are unchanged. The SHA-46 and SHA-65 tables above keep
the figures of their tickets.

### ML-DSA verify reproduce

Every command block starts from the repository root. For the Pico 2 W use
`benches/rp2350-mldsa`, board `rp2350` and target `thumbv8m.main-none-eabihf`.

Host tests (no board):

```sh
cargo test -p keelsign-verify --locked --features ml-dsa
cargo test -p keelsign-verify --locked --features ed25519,ml-dsa
cargo test -p policy-kat --locked --features keelsign-verify/ml-dsa
```

On-target (manual procedure, needs the board):

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked --features ml-dsa --test mldsa_verify
cargo test --release --locked --features ml-dsa --test policy -- policy_matrix_from_flash
cargo test --release --locked --test policy -- policy_matrix_from_flash
```

Expect five `MLDSA … result=Ok … saturated=false` lines and `MLDSA board=nrf52840
passed=5/5`, then `POLICY board=nrf52840 passed=156/156` from both policy runs. Copy each
set's largest `peak_stack=` and its `cycles=` into the results table.

Flash footprint (no board):

```sh
cd benches/nrf52840-mldsa
cargo build --release --locked --bins
cargo build --profile size --locked --bins
cargo build --release --locked --bins --features ml-dsa --target-dir target/mldsa
cargo build --profile size --locked --bins --features ml-dsa --target-dir target/mldsa
python3 ../../scripts/elf_sizes.py --label nrf52840/release/ml-dsa --baseline target/thumbv7em-none-eabihf/release/size_verify target/thumbv7em-none-eabihf/release/size_verify target/mldsa/thumbv7em-none-eabihf/release/size_verify
python3 ../../scripts/elf_sizes.py --label nrf52840/size/ml-dsa --baseline target/thumbv7em-none-eabihf/size/size_verify target/thumbv7em-none-eabihf/size/size_verify target/mldsa/thumbv7em-none-eabihf/size/size_verify
```

Static frames (nightly only, not run in CI):

```sh
cd benches/nrf52840-mldsa
cargo +nightly rustc --release --locked --features ml-dsa --bin size_verify --target-dir target/nightly-mldsa -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly-mldsa/thumbv7em-none-eabihf/release/size_verify --top 8 --match keelsign_verify
cargo +nightly rustc --profile size --locked --features ml-dsa --bin size_verify --target-dir target/nightly-mldsa -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly-mldsa/thumbv7em-none-eabihf/size/size_verify --top 8 --match keelsign_verify
cargo +nightly rustc --release --locked --bin size_verify --target-dir target/nightly -- -Z emit-stack-sizes
python3 ../../scripts/stack_frames.py target/nightly/thumbv7em-none-eabihf/release/size_verify --top 8 --match keelsign_verify
```
