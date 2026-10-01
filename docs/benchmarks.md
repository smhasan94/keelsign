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
