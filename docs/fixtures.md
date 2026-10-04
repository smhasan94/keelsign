# Test fixtures

Every committed fixture is script output (CLAUDE.md: fixtures are regenerated only by
script, never edited by hand). One wrapper, [`scripts/make-fixtures.sh`](../scripts/make-fixtures.sh),
runs every generator (SHA-39).

## Generators

| Script | Writes | Needs | Details |
|---|---|---|---|
| `scripts/gen_mldsa_vectors.py` | `benches/mldsa-kat/fixtures/` (ML-DSA KATs: NIST ACVP sigVer, Wycheproof) | network | [benchmarks.md](benchmarks.md) |
| `scripts/gen_lms_vectors.py` | `benches/lms-kat/fixtures/` (LMS/HSS KATs) | network | [benchmarks.md](benchmarks.md) |
| `scripts/gen_image_fixtures.py` | `tests/fixtures/images/` (MCUboot images with keelsign TLVs, the policy matrix) | network, imgtool 2.4.0 | [image-format.md](image-format.md#sample-images) |
| `scripts/gen_fuzz_corpus.py` | `fuzz/corpus/` (the `parse_image` seed corpus and its `MANIFEST.json`) | nothing (offline; reads `tests/fixtures/images/`) | [fuzzing.md](fuzzing.md#corpus) |
| `scripts/gen_inspect_snapshots.py` | `keelsign/tests/snapshots/inspect/` (`keelsign inspect` text and JSON output of seven sample images) | cargo, or a built binary with `--keelsign PATH` (offline; reads `tests/fixtures/images/`) | [signing.md](signing.md#inspect) |

Each takes `--check`, which regenerates into a temporary directory and diffs the result
with the committed files without writing anything. The "keelsign TLV encoder" the images
are built with is the Python encoder inside `gen_image_fixtures.py`.

## Regenerating every fixture

```sh
scripts/make-fixtures.sh --check --imgtool .venv-imgtool/bin/imgtool   # verify, writes nothing
scripts/make-fixtures.sh --imgtool .venv-imgtool/bin/imgtool           # rewrite every fixture
```

The wrapper runs the five generators in the order of the table (the fuzz corpus and the
inspect snapshots are built from the images, so they come after them), forwards `--check`,
`--imgtool PATH` (to the image generator only; without it imgtool is taken from `PATH`)
and `--keelsign PATH` (to the snapshot generator only; without it the binary is run with
`cargo run -q -p keelsign --locked --`), stops at the first failure, and
ends with `make-fixtures: every fixture matches a fresh regeneration` (check mode) or
`make-fixtures: regenerated every fixture` (write mode).

Write mode is byte-identical. RSA-PSS and ECDSA signatures are randomised, so the image
generator rebuilds those images from the signatures committed under
`tests/fixtures/images/sigs/` (`imgtool sign --fix-sig`); the wrapper never passes
`--resign`, which would sign afresh. To confirm a write-mode run changed nothing:

```sh
scripts/make-fixtures.sh --imgtool .venv-imgtool/bin/imgtool
git status --porcelain --untracked-files=all -- tests/fixtures benches/lms-kat/fixtures benches/mldsa-kat/fixtures fuzz/corpus
```

The second command prints nothing; add `keelsign/tests/snapshots` to the paths to cover
the inspect snapshots too. The repo-check
`repo_checks::fuzz::make_fixtures_check_regenerates_byte_identically` (ignored: it needs
the network and imgtool on `PATH`) runs the check mode:

```sh
PATH="$PWD/.venv-imgtool/bin:$PATH" cargo test -p repo-checks --locked --test fuzz -- --ignored
```

and `repo_checks::fuzz::make_fixtures_runs_every_generator` fails when a new
`scripts/gen_*.py` is not called by the wrapper.

## Prerequisites

- `python3`; the generators use only the standard library.
- Network access for the first three generators: they download pinned upstream vectors
  and the pinned independent signers (hsslms, dilithium-py) and check their sha256.
- imgtool 2.4.0 for the image generator, in a virtual environment:

  ```sh
  python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool==2.4.0
  ```

A full check takes about 20 seconds.

## Fuzz corpus

`scripts/gen_fuzz_corpus.py` copies every image under `tests/fixtures/images/` into
`fuzz/corpus/parse_image/` as `fixture-<name>.bin` (subdirectories joined with `-`),
except two files it lists in `EXCLUDED` and in `fuzz/corpus/MANIFEST.json`:
`mcuboot-ed25519-200k.bin` (205 KB, over the fuzzer's 8 KB input limit; otherwise the
layout of `mcuboot-ed25519.bin`) and `policy-matrix.bin` (an index, not an image). It adds
eleven small `synth-*.bin` seeds so that the corpus reaches every TLV kind and every error
variant. Rerun it whenever an image fixture is added or changed (`make-fixtures.sh` does);
the repo-check `repo_checks::fuzz::corpus_is_committed_and_matches_its_manifest` fails
until you do. See [fuzzing.md](fuzzing.md#corpus).
