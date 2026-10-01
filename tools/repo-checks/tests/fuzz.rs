//! SHA-39: the parse_image fuzz crate, its committed corpus, the fuzz workflow, the
//! fixture wrapper scripts/make-fixtures.sh and their docs.

use repo_checks::{python_script, run_capture, sha256_hex, workspace_root};
use std::fs;
use std::path::Path;
use std::process::Command;

/// The nightly toolchain cargo fuzz runs on in CI, also named in docs/fuzzing.md.
const FUZZ_TOOLCHAIN: &str = "nightly-2026-09-29";
/// The cargo-fuzz release CI installs.
const CARGO_FUZZ: &str = "cargo-fuzz@0.13.2";
/// Fixture files the corpus generator leaves out (scripts/gen_fuzz_corpus.py, EXCLUDED).
const EXCLUDED: [&str; 2] = ["mcuboot-ed25519-200k.bin", "policy-matrix.bin"];
/// Synthetic seeds: every TLV kind, one per ParseError variant, TLV areas over 4 KiB,
/// empty TLV areas.
const SYNTH_SEEDS: usize = 11;

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("git output is UTF-8")
}

/// (name, sha256, bytes) of every seed in fuzz/corpus/MANIFEST.json (`json.dumps`
/// with indent 2: a `"name.bin": {` line at four spaces, then fields at six).
fn manifest_seeds() -> Vec<(String, String, usize)> {
    let text = read("fuzz/corpus/MANIFEST.json");
    let mut seeds = Vec::new();
    let mut current: Option<(String, String, usize)> = None;
    for line in text.lines() {
        if let Some(name) = line
            .strip_prefix("    \"")
            .and_then(|l| l.strip_suffix("\": {"))
        {
            current = Some((name.to_owned(), String::new(), 0));
        } else if let Some(seed) = current.as_mut() {
            if let Some(v) = line.strip_prefix("      \"sha256\": \"") {
                seed.1 = v.trim_end_matches([',', '"']).to_owned();
            } else if let Some(v) = line.strip_prefix("      \"bytes\": ") {
                seed.2 = v.trim_end_matches(',').parse().expect("bytes");
            } else if line.starts_with("    }") {
                seeds.push(current.take().expect("open entry"));
            }
        }
    }
    seeds
}

/// Every `.bin` under tests/fixtures/images/, relative to it.
fn image_fixtures() -> Vec<String> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir)
            .expect("read fixture dir")
            .filter_map(Result::ok)
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.path().is_dir() {
                walk(&entry.path(), &rel, out);
            } else if rel.ends_with(".bin") {
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &workspace_root().join("tests/fixtures/images"),
        "",
        &mut out,
    );
    out.sort();
    out
}

/// SHA-39 AC2: the seed corpus is committed under fuzz/corpus/parse_image/, every seed
/// matches its MANIFEST.json entry (size and sha256), every image fixture but the two
/// excluded ones has its `fixture-` seed, and the corpus is exactly the generator's
/// output.
#[test]
fn corpus_is_committed_and_matches_its_manifest() {
    let root = workspace_root();
    let seeds = manifest_seeds();
    let tracked = git(&["ls-files", "--", "fuzz/corpus"]);
    let tracked: Vec<&str> = tracked.lines().collect();
    assert!(
        tracked.contains(&"fuzz/corpus/MANIFEST.json"),
        "MANIFEST.json is committed"
    );
    for (name, sha256, bytes) in &seeds {
        let rel = format!("fuzz/corpus/parse_image/{name}");
        assert!(tracked.contains(&rel.as_str()), "{rel} is not committed");
        let data = fs::read(root.join(&rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert_eq!(data.len(), *bytes, "{rel}: size");
        assert_eq!(&sha256_hex(&data), sha256, "{rel}: sha256");
    }
    // Nothing committed in the input directory that the manifest does not list.
    for rel in &tracked {
        if let Some(name) = rel.strip_prefix("fuzz/corpus/parse_image/") {
            assert!(
                seeds.iter().any(|(n, _, _)| n == name),
                "{rel} is committed but not in fuzz/corpus/MANIFEST.json"
            );
        }
    }
    // One fixture seed per image fixture, except the excluded ones; then the synth seeds.
    let fixtures = image_fixtures();
    for excluded in EXCLUDED {
        assert!(
            fixtures.iter().any(|f| f == excluded),
            "{excluded} still exists"
        );
    }
    let expected: Vec<String> = fixtures
        .iter()
        .filter(|f| !EXCLUDED.contains(&f.as_str()))
        .map(|f| format!("fixture-{}", f.replace('/', "-")))
        .collect();
    let fixture_seeds: Vec<&String> = seeds
        .iter()
        .map(|(n, _, _)| n)
        .filter(|n| n.starts_with("fixture-"))
        .collect();
    assert_eq!(
        fixture_seeds.len(),
        expected.len(),
        "fixture seeds vs image fixtures; rerun python3 scripts/gen_fuzz_corpus.py"
    );
    for name in &expected {
        assert!(
            fixture_seeds.contains(&name),
            "no seed {name}; rerun python3 scripts/gen_fuzz_corpus.py"
        );
    }
    let synth = seeds
        .iter()
        .filter(|(n, _, _)| n.starts_with("synth-"))
        .count();
    assert_eq!(synth, SYNTH_SEEDS, "synth seeds");
    assert_eq!(seeds.len(), expected.len() + SYNTH_SEEDS);
    // No seed is longer than the fuzzer's -max_len.
    assert!(seeds.iter().all(|(_, _, bytes)| *bytes <= 8192));

    let (ok, stdout, stderr) = run_capture(python_script("gen_fuzz_corpus.py").arg("--check"));
    assert!(ok, "gen_fuzz_corpus.py --check failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("fuzz corpus matches a fresh regeneration"),
        "{stdout}"
    );
}

/// The text of the job `name` in a workflow: from its `  name:` line up to the next
/// line indented by exactly two spaces (the next job, or a comment before it).
fn job<'a>(workflow: &'a str, name: &str) -> &'a str {
    let start = workflow
        .find(&format!("\n  {name}:\n"))
        .unwrap_or_else(|| panic!("no job {name}"));
    let body = &workflow[start + 1..];
    let end = body
        .match_indices('\n')
        .map(|(i, _)| i)
        .find(|&i| {
            let rest = &body[i + 1..];
            rest.starts_with("  ") && !rest.starts_with("   ")
        })
        .unwrap_or(body.len());
    &body[..end]
}

/// SHA-39 AC2 and TP3: .github/workflows/fuzz.yml runs the smoke on every PR and the
/// 30-minute run nightly (schedule and manual dispatch), on the pinned nightly with the
/// pinned cargo-fuzz; the nightly job always summarises and uploads the artifacts,
/// including the tarball that keeps the (empty when healthy) crash directory, then runs
/// the TP1 self-test and the coverage check.
#[test]
fn fuzz_workflow_runs_smoke_on_prs_and_nightly() {
    let wf = read(".github/workflows/fuzz.yml");
    for trigger in [
        "\n  pull_request:\n",
        "\n  schedule:\n    - cron: \"17 3 * * *\"\n",
        "\n  workflow_dispatch:\n",
    ] {
        assert!(wf.contains(trigger), "fuzz.yml lacks trigger {trigger:?}");
    }
    assert!(wf.contains(&format!("FUZZ_TOOLCHAIN: {FUZZ_TOOLCHAIN}")));
    assert!(wf.contains("cancel-in-progress: ${{ github.event_name == 'pull_request' }}"));

    let check = job(&wf, "fuzz-check");
    for step in [
        "cargo fmt --manifest-path fuzz/Cargo.toml --check",
        "cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings",
        "cargo test --manifest-path fuzz/Cargo.toml --locked",
        "python3 scripts/gen_fuzz_corpus.py --check",
        "python3 scripts/fuzz_coverage_check.py --self-test",
    ] {
        assert!(check.contains(step), "fuzz-check lacks {step}");
    }
    assert!(!check.contains("if:"), "fuzz-check runs on every event");

    let smoke = job(&wf, "fuzz-smoke");
    assert!(smoke.contains("if: github.event_name == 'pull_request'"));
    assert!(smoke.contains("run: scripts/fuzz.sh smoke"));

    let nightly = job(&wf, "fuzz-nightly");
    assert!(nightly.contains(
        "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    ));
    assert!(nightly.contains("timeout-minutes: 60"));
    assert!(nightly.contains("components: llvm-tools-preview"));
    for job_text in [smoke, nightly] {
        assert!(job_text.contains(&format!("toolchain: {FUZZ_TOOLCHAIN}")));
        assert!(job_text.contains("uses: taiki-e/cache-cargo-install-action@v2"));
        assert!(job_text.contains(&format!("tool: {CARGO_FUZZ}")));
    }
    // In order: the run, the summary (always), the upload (always), TP1, coverage.
    let order = [
        "run: scripts/fuzz.sh nightly",
        "if: always()\n        run: scripts/fuzz.sh summary",
        "name: fuzz-nightly-${{ github.run_id }}",
        "fuzz/artifacts/summary.txt",
        "fuzz/fuzz-artifacts.tar.gz",
        "retention-days: 30",
        "run: scripts/fuzz.sh tp1",
        "run: scripts/fuzz.sh coverage",
    ];
    let mut at = 0;
    for needle in order {
        let found = nightly[at..]
            .find(needle)
            .unwrap_or_else(|| panic!("fuzz-nightly lacks (or misorders) {needle:?}"));
        at += found + needle.len();
    }
    let upload = &nightly[nightly
        .find("name: upload nightly artifacts")
        .expect("upload step")..];
    assert!(upload.starts_with("name: upload nightly artifacts\n        if: always()"));

    // The summary keeps the crash directory: created even when empty, tarred whole, and
    // counted in summary.txt.
    let sh = read("scripts/fuzz.sh");
    assert!(sh.contains("mkdir -p \"$ARTIFACTS/$TARGET\""));
    assert!(sh.contains("tar -czf \"$TARBALL\" -C fuzz artifacts"));
    assert!(sh.contains("TARBALL=fuzz/fuzz-artifacts.tar.gz"));
    assert!(sh.contains("crash_files="));
    assert!(sh.contains("smoke) run \"${FUZZ_SECONDS:-120}\""));
    assert!(sh.contains("nightly) run \"${FUZZ_SECONDS:-1800}\""));
    assert!(sh.contains("LIBFUZZER_ARGS=(-timeout=10 -max_len=8192 -print_final_stats=1)"));
}

/// SHA-39 AC2: the fuzz crate is a standalone workspace (not a root member), pins
/// libfuzzer-sys, forbids unsafe code in its manifest and in every crate root, and
/// keeps its own Cargo.lock.
#[test]
fn fuzz_crate_is_standalone_pinned_and_forbids_unsafe() {
    let manifest = read("fuzz/Cargo.toml");
    for line in [
        "name = \"keelsign-fuzz\"",
        "publish = false",
        "cargo-fuzz = true",
        "\n[workspace]\n",
        "keelsign-verify = { path = \"../keelsign-verify\" }",
        "libfuzzer-sys = \"=0.4.13\"",
        "\n[lints.rust]\nunsafe_code = \"forbid\"\n",
        "name = \"parse_image\"",
    ] {
        assert!(manifest.contains(line), "fuzz/Cargo.toml lacks {line:?}");
    }
    let lock = read("fuzz/Cargo.lock");
    assert!(lock.contains("name = \"libfuzzer-sys\"\nversion = \"0.4.13\""));
    assert!(lock.contains("name = \"keelsign-fuzz\""));
    assert!(
        !lock.contains("name = \"ml-dsa\""),
        "the parser needs no ML-DSA"
    );

    let root = read("Cargo.toml");
    let members = &root[root.find("members = [").expect("members")..];
    let members = &members[..members.find(']').expect("members end")];
    assert!(
        !members.contains("\"fuzz\""),
        "fuzz/ must not be a root workspace member"
    );
    assert!(
        !read("Cargo.lock").contains("libfuzzer-sys"),
        "root lock has no fuzz deps"
    );

    for rel in ["fuzz/src/lib.rs", "fuzz/fuzz_targets/parse_image.rs"] {
        let text = read(rel);
        assert!(text.contains("#![forbid(unsafe_code)]"), "{rel}");
    }
    for dir in ["fuzz/src", "fuzz/fuzz_targets"] {
        for entry in fs::read_dir(workspace_root().join(dir)).expect("read dir") {
            let path = entry.expect("entry").path();
            let text = fs::read_to_string(&path).expect("read source");
            for word in ["unsafe {", "unsafe fn", "unsafe impl", "allow(unsafe_code)"] {
                assert!(!text.contains(word), "{}: {word}", path.display());
            }
        }
    }
}

/// SHA-39 TP1 (supporting): the injected off-by-one still applies to the parser
/// (`scripts/fuzz.sh tp1` applies it to a copy of HEAD), and it touches only the TLV
/// length check in keelsign-verify/src/image.rs.
#[test]
fn tp1_patch_applies_to_the_parser() {
    let patch = read("fuzz/tp1-tlv-length-off-by-one.patch");
    let files: Vec<&str> = patch
        .lines()
        .filter_map(|l| l.strip_prefix("+++ b/"))
        .collect();
    assert_eq!(files, ["keelsign-verify/src/image.rs"]);
    assert!(patch.contains("@@ fn split_tlv("));
    assert!(patch.contains("+    if len > tail.len() + 1 {"));
    git(&["apply", "--check", "fuzz/tp1-tlv-length-off-by-one.patch"]);
    let sh = read("scripts/fuzz.sh");
    assert!(sh.contains("TP1_PATCH=fuzz/tp1-tlv-length-off-by-one.patch"));
    assert!(sh.contains("TP1_SECONDS=120"));
    assert!(sh.contains("git archive HEAD"));
    // The message tp1 waits for is the harness's disagreement panic.
    let lib = read("fuzz/src/lib.rs");
    assert!(lib.contains(
        "pub const DISAGREEMENT: &str = \"Image::parse disagrees with the reference parser\";"
    ));
    assert!(sh.contains("DISAGREEMENT=\"Image::parse disagrees with the reference parser\""));
}

/// SHA-39 AC3 (supporting): scripts/make-fixtures.sh runs every `scripts/gen_*.py`,
/// stops on the first failure, and never re-signs.
#[test]
fn make_fixtures_runs_every_generator() {
    let sh = read("scripts/make-fixtures.sh");
    assert!(sh.contains("\nset -euo pipefail\n"));
    assert!(
        !sh.contains("--resign\n") && !sh.contains("--resign "),
        "never --resign"
    );
    let mut generators = Vec::new();
    for entry in fs::read_dir(workspace_root().join("scripts")).expect("read scripts") {
        let name = entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.starts_with("gen_") && name.ends_with(".py") {
            generators.push(name);
        }
    }
    generators.sort();
    assert!(generators.len() >= 4, "{generators:?}");
    for generator in &generators {
        assert!(
            sh.contains(&format!("run python3 scripts/{generator}")),
            "scripts/make-fixtures.sh does not run {generator}"
        );
    }
    // The fuzz corpus is built from the images, so it comes after them.
    let images = sh
        .find("run python3 scripts/gen_image_fixtures.py")
        .expect("images");
    let corpus = sh
        .find("run python3 scripts/gen_fuzz_corpus.py")
        .expect("corpus");
    assert!(images < corpus);
}

/// SHA-39 AC3: `scripts/make-fixtures.sh --check` regenerates every fixture
/// byte-identically. Needs the network and imgtool 2.4.0 on `PATH` (docs/fixtures.md).
#[test]
#[ignore = "needs the network and imgtool 2.4.0 on PATH"]
fn make_fixtures_check_regenerates_byte_identically() {
    let root = workspace_root();
    let (ok, stdout, stderr) = run_capture(
        Command::new("bash")
            .current_dir(&root)
            .arg(root.join("scripts/make-fixtures.sh"))
            .arg("--check"),
    );
    assert!(ok, "make-fixtures.sh --check failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("make-fixtures: every fixture matches a fresh regeneration"),
        "{stdout}"
    );
}

/// docs/fuzzing.md and docs/fixtures.md have their sections, name the pinned toolchain
/// (the one fuzz.yml uses) and cargo-fuzz release, and give the AC1, TP1 and TP2
/// commands.
#[test]
fn fuzzing_and_fixtures_docs_have_required_sections() {
    let fuzzing = read("docs/fuzzing.md");
    for heading in [
        "## Prerequisites",
        "## Layout",
        "## Corpus",
        "## Running",
        "## Ten-minute local run (AC1)",
        "## Injected off-by-one (TP1)",
        "## Coverage (TP2)",
        "## CI jobs (AC2, TP3)",
        "## Reproducing a crash",
    ] {
        assert!(
            fuzzing.contains(&format!("\n{heading}\n")),
            "docs/fuzzing.md lacks {heading}"
        );
    }
    assert!(read(".github/workflows/fuzz.yml").contains(FUZZ_TOOLCHAIN));
    for text in [
        FUZZ_TOOLCHAIN,
        "cargo-fuzz 0.13.2",
        "cargo install cargo-fuzz --version 0.13.2 --locked",
        "rustup component add llvm-tools-preview",
        "cargo +nightly fuzz run parse_image -- -max_total_time=600 -timeout=10 -max_len=8192 -print_final_stats=1",
        "scripts/fuzz.sh run 600",
        "scripts/fuzz.sh tp1",
        "scripts/fuzz.sh coverage",
        "scripts/fuzz.sh summary",
        "crash_files=0",
    ] {
        assert!(fuzzing.contains(text), "docs/fuzzing.md lacks {text:?}");
    }

    let fixtures = read("docs/fixtures.md");
    for heading in [
        "## Generators",
        "## Regenerating every fixture",
        "## Prerequisites",
        "## Fuzz corpus",
    ] {
        assert!(
            fixtures.contains(&format!("\n{heading}\n")),
            "docs/fixtures.md lacks {heading}"
        );
    }
    for text in [
        "scripts/make-fixtures.sh --check",
        "scripts/gen_mldsa_vectors.py",
        "scripts/gen_lms_vectors.py",
        "scripts/gen_image_fixtures.py",
        "scripts/gen_fuzz_corpus.py",
        "imgtool==2.4.0",
        "git status --porcelain --untracked-files=all -- tests/fixtures benches/lms-kat/fixtures benches/mldsa-kat/fixtures fuzz/corpus",
    ] {
        assert!(fixtures.contains(text), "docs/fixtures.md lacks {text:?}");
    }
}
