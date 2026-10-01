#!/usr/bin/env bash
# Regenerate (or, with --check, verify) every committed fixture, in dependency order:
#
#   1. scripts/gen_mldsa_vectors.py   ML-DSA KATs     benches/mldsa-kat/fixtures/  (network)
#   2. scripts/gen_lms_vectors.py     LMS/HSS KATs    benches/lms-kat/fixtures/    (network)
#   3. scripts/gen_image_fixtures.py  MCUboot images  tests/fixtures/images/       (network, imgtool 2.4.0)
#   4. scripts/gen_fuzz_corpus.py     fuzz seeds      fuzz/corpus/                 (offline, from 3)
#
# Usage:
#   scripts/make-fixtures.sh [--imgtool PATH]           # rewrite every fixture
#   scripts/make-fixtures.sh --check [--imgtool PATH]   # regenerate into temp dirs and diff
#
# Write mode is byte-identical: the image generator reuses the committed classical
# signatures under tests/fixtures/images/sigs/ (it is never passed --resign), so
# `git status` stays clean. docs/fixtures.md has the details and prerequisites.
set -euo pipefail

usage() {
    echo "usage: scripts/make-fixtures.sh [--check] [--imgtool PATH]" >&2
    exit 2
}

check=()
imgtool=()
while [ $# -gt 0 ]; do
    case "$1" in
        --check) check=(--check) ;;
        --imgtool)
            [ $# -ge 2 ] || usage
            imgtool=(--imgtool "$2")
            shift
            ;;
        *) usage ;;
    esac
    shift
done

cd "$(dirname "$0")/.."

run() {
    echo "make-fixtures: $*"
    "$@"
}

run python3 scripts/gen_mldsa_vectors.py ${check[@]+"${check[@]}"}
run python3 scripts/gen_lms_vectors.py ${check[@]+"${check[@]}"}
run python3 scripts/gen_image_fixtures.py ${check[@]+"${check[@]}"} ${imgtool[@]+"${imgtool[@]}"}
run python3 scripts/gen_fuzz_corpus.py ${check[@]+"${check[@]}"}

if [ ${#check[@]} -gt 0 ]; then
    echo "make-fixtures: every fixture matches a fresh regeneration"
else
    echo "make-fixtures: regenerated every fixture"
fi
