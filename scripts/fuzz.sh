#!/usr/bin/env bash
# Run the parse_image fuzz target (fuzz/, SHA-39). docs/fuzzing.md has the details.
#
# Usage: scripts/fuzz.sh COMMAND
#   smoke        fuzz for 120 s (the PR job)
#   nightly      fuzz for 1800 s (the nightly job)
#   run SECS     fuzz for SECS seconds
#   summary      write fuzz/artifacts/summary.txt and fuzz/fuzz-artifacts.tar.gz
#   tp1          check that the fuzzer finds the injected off-by-one
#                (fuzz/tp1-tlv-length-off-by-one.patch) within 120 s
#   coverage     coverage of the committed corpus, checked by scripts/fuzz_coverage_check.py
#
# Environment:
#   FUZZ_TOOLCHAIN  the nightly toolchain to use (default: nightly; CI pins one)
#   FUZZ_SECONDS    overrides the duration of smoke and nightly
#
# The fuzzer writes new inputs to fuzz/corpus-work/parse_image (gitignored) and reads the
# committed seeds from fuzz/corpus/parse_image; crashes go to fuzz/artifacts/parse_image/
# and the log to fuzz/artifacts/run.log.
set -euo pipefail

cd "$(dirname "$0")/.."

TC="${FUZZ_TOOLCHAIN:-nightly}"
TARGET=parse_image
CORPUS="fuzz/corpus/$TARGET"
WORK="fuzz/corpus-work/$TARGET"
ARTIFACTS=fuzz/artifacts
TARBALL=fuzz/fuzz-artifacts.tar.gz
LIBFUZZER_ARGS=(-timeout=10 -max_len=8192 -print_final_stats=1)
TP1_PATCH=fuzz/tp1-tlv-length-off-by-one.patch
TP1_SECONDS=120
# The panic message of keelsign_fuzz::check_parse_image (fuzz/src/lib.rs, DISAGREEMENT).
DISAGREEMENT="Image::parse disagrees with the reference parser"

usage() {
    sed -n '4,15p' "$0" >&2
    exit 2
}

fetch() {
    # cargo fuzz has no --locked: fetch with it first, so the build uses fuzz/Cargo.lock.
    cargo "+$TC" fetch --manifest-path fuzz/Cargo.toml --locked
}

run() {
    local secs="$1"
    case "$secs" in
        '' | *[!0-9]* | 0 | 0*)
            echo "fuzz.sh: seconds must be a positive integer, not '$secs'" >&2
            usage
            ;;
    esac
    fetch
    mkdir -p "$WORK" "$ARTIFACTS/$TARGET"
    echo "fuzz.sh: target=$TARGET seconds=$secs toolchain=$TC" | tee "$ARTIFACTS/run.log"
    cargo "+$TC" fuzz run "$TARGET" "$WORK" "$CORPUS" -- \
        -max_total_time="$secs" "${LIBFUZZER_ARGS[@]}" 2>&1 | tee -a "$ARTIFACTS/run.log"
}

summary() {
    mkdir -p "$ARTIFACTS/$TARGET"
    local log="$ARTIFACTS/run.log" out="$ARTIFACTS/summary.txt" crashes
    crashes="$(cd "$ARTIFACTS/$TARGET" && find . -type f | sed 's|^\./||' | sort)"
    {
        echo "target=$TARGET"
        echo "toolchain=$(rustc "+$TC" -V)"
        echo "cargo_fuzz=$(cargo "+$TC" fuzz --version)"
        if [ -f "$log" ]; then
            sed -n 's/^fuzz\.sh: .*\(seconds=[0-9]*\).*/\1/p' "$log" | head -n 1
            grep -E '^Done [0-9]+ runs in [0-9]+ second' "$log" || echo "Done: none (the run stopped early; see run.log)"
        else
            echo "run.log: missing (no run)"
        fi
        echo "crash_files=$(printf '%s' "$crashes" | grep -c . || true)"
        if [ -n "$crashes" ]; then
            printf '%s\n' "$crashes" | sed "s|^|  $TARGET/|"
        fi
        if [ -f "$log" ]; then
            grep '^stat::' "$log" || true
        fi
    } > "$out"
    # A tarball keeps the crash directory even when it is empty (healthy).
    tar -czf "$TARBALL" -C fuzz artifacts
    cat "$out"
    echo "fuzz.sh: wrote $out and $TARBALL"
}

tp1() {
    local log status start elapsed execs
    TP1_DIR="$(mktemp -d "${TMPDIR:-/tmp}/keelsign-tp1.XXXXXX")"
    trap 'rm -rf "$TP1_DIR"' EXIT
    # The committed tree (HEAD), with the bug applied to the copy only.
    git archive HEAD | tar -x -C "$TP1_DIR"
    (cd "$TP1_DIR" && GIT_CEILING_DIRECTORIES="$(dirname "$TP1_DIR")" git apply "$TP1_PATCH")
    echo "tp1: $TP1_PATCH applied to a copy of HEAD in $TP1_DIR"
    (cd "$TP1_DIR" && cargo "+$TC" fetch --manifest-path fuzz/Cargo.toml --locked && cargo "+$TC" fuzz build "$TARGET")
    mkdir -p "$TP1_DIR/$WORK" "$ARTIFACTS"
    log="$ARTIFACTS/tp1.log"
    start=$SECONDS
    set +e
    (cd "$TP1_DIR" && cargo "+$TC" fuzz run "$TARGET" "$WORK" "$CORPUS" -- \
        -max_total_time="$TP1_SECONDS" "${LIBFUZZER_ARGS[@]}") > "$log" 2>&1
    status=$?
    set -e
    elapsed=$((SECONDS - start))
    execs="$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | tail -n 1)"
    if [ "$status" -ne 0 ] && grep -q "$DISAGREEMENT" "$log" && [ "$elapsed" -le "$TP1_SECONDS" ]; then
        grep -m 1 "$DISAGREEMENT" "$log"
        echo "tp1: PASS: the injected off-by-one was found in $elapsed s (${execs:-?} executions; limit $TP1_SECONDS s)"
    else
        tail -n 40 "$log"
        echo "tp1: FAIL: exit $status after $elapsed s; no \"$DISAGREEMENT\" crash within $TP1_SECONDS s (log: $log)" >&2
        exit 1
    fi
}

coverage() {
    local host llvm_cov out bin
    fetch
    host="$(rustc "+$TC" -vV | sed -n 's/^host: //p')"
    llvm_cov="$(rustc "+$TC" --print sysroot)/lib/rustlib/$host/bin/llvm-cov"
    if [ ! -x "$llvm_cov" ]; then
        echo "fuzz.sh: no $llvm_cov; run: rustup component add llvm-tools-preview --toolchain $TC" >&2
        exit 1
    fi
    # Without --target-dir, cargo fuzz coverage builds under ./target of the current
    # directory (the root workspace's); keep it in the fuzz crate's own target.
    cargo "+$TC" fuzz coverage --target-dir fuzz/target/coverage "$TARGET" "$CORPUS"
    out="fuzz/coverage/$TARGET"
    bin="fuzz/target/coverage/$host/release/$TARGET"
    local args=("$bin" -instr-profile="$out/coverage.profdata" -show-instantiations=false
        -ignore-filename-regex='/\.cargo/registry/|/rustc/')
    "$llvm_cov" show "${args[@]}" > "$out/coverage.txt"
    "$llvm_cov" show "${args[@]}" -format=html -output-dir="$out/html"
    "$llvm_cov" report "$bin" -instr-profile="$out/coverage.profdata" \
        -ignore-filename-regex='/\.cargo/registry/|/rustc/' > "$out/report.txt"
    echo "fuzz.sh: coverage report in $out/ (coverage.txt, report.txt, html/)"
    python3 scripts/fuzz_coverage_check.py "$out/coverage.txt"
}

[ $# -ge 1 ] || usage
case "$1" in
    smoke) run "${FUZZ_SECONDS:-120}" ;;
    nightly) run "${FUZZ_SECONDS:-1800}" ;;
    run)
        [ $# -eq 2 ] || usage
        run "$2"
        ;;
    summary) summary ;;
    tp1) tp1 ;;
    coverage) coverage ;;
    *) usage ;;
esac
