# On-target test suite (SHA-47)

The on-target suite is every `embedded-test` binary in the two bench projects,
`benches/nrf52840-mldsa` (nRF52840-DK, `thumbv7em-none-eabihf`) and
`benches/rp2350-mldsa` (Pico 2 W, `thumbv8m.main-none-eabihf`). Both projects have the
same five test binaries and the same tests. They run on the board through the
`probe-rs run` runner in each project's `.cargo/config.toml`, which flashes each test
binary and runs every test case after a reset (setup: [setup.md](setup.md#on-target-tests-embedded-test)).
The fixtures are embedded in the test binaries with `include_bytes!` and the image tests
read them back through `NorFlashReader` over the board's flash driver.

CI builds and lints every test binary in both feature states (the `cross-build` job) but
never runs them: running the suite needs the boards, so it is the manual procedure
below. An on-device CI job is a later ticket (E8.1).

## Suite

| Binary | Tests | Ticket | Feature state | Log lines to look for |
|---|---|---|---|---|
| `tests/kat.rs` | `dwt_cycle_counter_present`, `mldsa44_kat`, `mldsa65_kat`, `mldsa44_bench`, `mldsa65_bench` | SHA-34 | both | `KAT board=… result=ok` per case; `BENCH board=… set=ML-DSA-44 … saturated=false` per case |
| `tests/lms.rs` | `lms_kat`, `lms_rotation_key_b_verifies_against_a_b_and_fails_against_a`, `lms_bench` | SHA-65, SHA-240 | both | `KAT board=… set=LMS … result=ok`; `ROTATION board=… … ok`; `BENCH board=… set=LMS-… saturated=false` |
| `tests/image.rs` | `image_digest_200k_from_flash`, `image_digest_bench` | SHA-42 (E3.1) | both | `DIGEST board=… from_flash=ok sha256_tlv=ok chunks=64,256,4096 ok`; `DIGEST board=… bytes=204800 chunk=256 cycles=… peak_stack=… saturated=false` |
| `tests/policy.rs` | `policy_matrix_from_flash`, `hybrid_verify_bench` | SHA-46 (E3.2), SHA-69 | both | `POLICY board=… passed=171/171` and no `result=FAIL`; `BENCH board=… set=Hybrid-… ok=true … saturated=false` per hybrid image |
| `tests/mldsa_verify.rs` | `mldsa_images_from_flash` | SHA-44 (E3.3) | `--features ml-dsa` only | `MLDSA board=… passed=5/5` |

Without the bench `ml-dsa` feature the suite is 12 tests; with it, 13 (the policy matrix
then verifies its ML-DSA cells instead of expecting the feature-off verdicts, and
`mldsa_verify` is built). The ML-DSA feature build goes to its own target directory,
`target/mldsa`, as in CI, so the feature-off build is untouched.

## Run the suite

Every command block starts from the repository root, with the board connected as in
[setup.md, Flash and run](setup.md#flash-and-run). The tests refuse to build without
`--release`. `.cargo/config.toml` sets the build target, so no `--target` is needed.

nRF52840-DK, feature off, then `ml-dsa`:

```sh
cd benches/nrf52840-mldsa
cargo test --release --locked 2>&1 | tee ../../docs/bench-logs/nrf52840-suite-run1.txt
cargo test --release --locked --features ml-dsa --target-dir target/mldsa 2>&1 | tee ../../docs/bench-logs/nrf52840-suite-mldsa-run1.txt
```

Pico 2 W (RP2350, through the Raspberry Pi Debug Probe), feature off, then `ml-dsa`:

```sh
cd benches/rp2350-mldsa
cargo test --release --locked 2>&1 | tee ../../docs/bench-logs/rp2350-suite-run1.txt
cargo test --release --locked --features ml-dsa --target-dir target/mldsa 2>&1 | tee ../../docs/bench-logs/rp2350-suite-mldsa-run1.txt
```

Check one run (it lists each test and its verdict, and fails on any verdict other than
`ok`):

```sh
python3 scripts/suite_results.py docs/bench-logs/nrf52840-suite-run1.txt
```

## P1: three identical runs per board (NEEDS-HARDWARE)

1. On each board, run both commands above three times, saving the logs as
   `docs/bench-logs/<board>-suite-run{1,2,3}.txt` and
   `docs/bench-logs/<board>-suite-mldsa-run{1,2,3}.txt` (`<board>` is `nrf52840` or
   `rp2350`; change `run1` in the `tee` path for each run). Reset nothing between runs:
   `probe-rs run` flashes and resets the board itself.
2. Compare the three runs of each board and feature state against the suite's test
   names (`--expect` is required, so a test missing from all three runs still fails):

   ```sh
   SUITE=dwt_cycle_counter_present,mldsa44_kat,mldsa65_kat,mldsa44_bench,mldsa65_bench,lms_kat,lms_bench,lms_rotation_key_b_verifies_against_a_b_and_fails_against_a,image_digest_200k_from_flash,image_digest_bench,policy_matrix_from_flash,hybrid_verify_bench
   SUITE_MLDSA="$SUITE,mldsa_images_from_flash"
   python3 scripts/suite_results.py --check-identical --expect "$SUITE" docs/bench-logs/nrf52840-suite-run1.txt docs/bench-logs/nrf52840-suite-run2.txt docs/bench-logs/nrf52840-suite-run3.txt
   python3 scripts/suite_results.py --check-identical --expect "$SUITE_MLDSA" docs/bench-logs/nrf52840-suite-mldsa-run1.txt docs/bench-logs/nrf52840-suite-mldsa-run2.txt docs/bench-logs/nrf52840-suite-mldsa-run3.txt
   python3 scripts/suite_results.py --check-identical --expect "$SUITE" docs/bench-logs/rp2350-suite-run1.txt docs/bench-logs/rp2350-suite-run2.txt docs/bench-logs/rp2350-suite-run3.txt
   python3 scripts/suite_results.py --check-identical --expect "$SUITE_MLDSA" docs/bench-logs/rp2350-suite-mldsa-run1.txt docs/bench-logs/rp2350-suite-mldsa-run2.txt docs/bench-logs/rp2350-suite-mldsa-run3.txt
   ```

   Each prints `identical: N tests ok in all 3 logs` (12, or 13 with `ml-dsa`). It fails
   if an expected test is missing from any run, a test's verdict differs between runs, or
   any verdict is not `ok`.
3. Run the repo-check, which does the same for all twelve logs with the full test list
   of each feature state:

   ```sh
   cargo test -p repo-checks --locked --test on_target -- --ignored three_suite_runs_identical_per_board
   ```

4. Commit the twelve logs. The first real log also validates the log format the script
   assumes (`test <name> ... ok`, as embedded-test 0.7.2 prints it through probe-rs
   0.32.0); if probe-rs prints it differently, adapt `scripts/suite_results.py` and its
   synthetic-log repo-check to the real format.

## P2: peak stack and cycles (NEEDS-HARDWARE)

The suite logs carry the measured figures that are still `pending (hardware)` in
[benchmarks.md](benchmarks.md). From the `run1` logs of each board:

- ML-DSA and LMS/HSS: summarise the `BENCH` lines with
  `python3 scripts/bench_summarize.py docs/bench-logs/<board>-suite-run1.txt` and copy
  the headline cycles, time and peak stack into [Results](benchmarks.md#results) and
  [LMS results](benchmarks.md#lms-results).
- Image digest: copy `cycles=`, `us=` and `peak_stack=` of the
  `DIGEST board=… bytes=204800` line into [Digest results](benchmarks.md#digest-results).
- ML-DSA verify: copy each set's largest `peak_stack=` and its `cycles=` from the
  `MLDSA board=… image=…` lines of `<board>-suite-mldsa-run1.txt` into
  [ML-DSA verify results](benchmarks.md#ml-dsa-verify-results).
- Hybrid verify (SHA-69): copy `cycles=` and `peak_stack=` of the two
  `BENCH board=… set=Hybrid-…` lines of `hybrid_verify_bench` into
  [Hybrid per-image results](benchmarks.md#hybrid-per-image-results), and the L=1 line
  (`set=Hybrid-Ed25519+LMS-M32_H5-L1`) into [Hybrid results](benchmarks.md#hybrid-results).
  `python3 scripts/bench_summarize.py docs/bench-logs/<board>-suite-run1.txt` lists them
  with the LMS/HSS and ML-DSA sets.
- Copy the same figures into the matching cells of
  [RAM/flash budget (SHA-47)](benchmarks.md#ramflash-budget-sha-47).

SHA-69 added `hybrid_verify_bench`; the hybrid cells are `pending (hardware)` until P2.
SHA-47's AC3 is ticked on the recorded flash and static-frame figures plus the measured
LMS/HSS, ML-DSA and digest cells that P2 fills in.

The three-run consistency check of the benchmarks
([benchmarks.md, Three-run consistency](benchmarks.md#three-run-consistency)) is separate:
it compares the `BENCH` figures within 5 %, while P1 compares the test verdicts.

## Repo-checks

`tools/repo-checks/tests/on_target.rs`:

- `suite_doc_lists_every_test_and_command`: this document lists every on-target test
  defined in both bench projects, each binary and the run and check commands for both
  boards and both feature states.
- `suite_results_checks_synthetic_logs`: `scripts/suite_results.py` accepts identical
  passing runs and rejects a missing test, a verdict that differs between runs, a failed
  test and a log without test lines.
- `three_suite_runs_identical_per_board` (ignored, NEEDS-HARDWARE): step 3 of P1.
