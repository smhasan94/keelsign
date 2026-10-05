//! Shared helpers for the keelsign repository checks. Not published.
//!
//! The checks themselves live in `tests/`.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Crates published to crates.io, in publish order; keelsign depends on keelsign-verify.
pub const PUBLISHABLE_CRATES: [&str; 2] = ["keelsign-verify", "keelsign"];

/// Crates that carry their own copies of the root licence files: the published ones and
/// keelsign-embassy (SHA-55; publishable, not yet published).
pub const LICENSED_CRATES: [&str; 3] = ["keelsign", "keelsign-verify", "keelsign-embassy"];

/// A standalone embedded example project under `examples/`.
pub struct Example {
    /// Directory name under `examples/`, and the package name.
    pub name: &'static str,
    /// Rust target triple the example is built for.
    pub target: &'static str,
    /// probe-rs chip name passed to `probe-rs run --chip`.
    pub chip: &'static str,
    /// The HAL crate feature that selects the board's chip.
    pub hal_feature: &'static str,
}

/// The embedded examples, one per development board.
pub const EXAMPLES: [Example; 2] = [
    Example {
        name: "nrf52840-hello",
        target: "thumbv7em-none-eabihf",
        chip: "nRF52840_xxAA",
        hal_feature: "nrf52840",
    },
    Example {
        name: "rp2350-hello",
        target: "thumbv8m.main-none-eabihf",
        chip: "RP235x",
        hal_feature: "rp235xa",
    },
];

/// The standalone embassy-boot applications under `examples/` (SHA-55), one per
/// development board: they verify the DFU slot with keelsign-embassy before marking it
/// (docs/embassy.md). `chip` is the probe-rs chip name, `hal_feature` the HAL chip feature.
pub const BOOT_EXAMPLES: [Example; 2] = [
    Example {
        name: "nrf52840-boot-app",
        target: "thumbv7em-none-eabihf",
        chip: "nRF52840_xxAA",
        hal_feature: "nrf52840",
    },
    Example {
        name: "rp2350-boot-app",
        target: "thumbv8m.main-none-eabihf",
        chip: "RP235x",
        hal_feature: "rp235xa",
    },
];

/// The standalone on-target benchmark projects under `benches/` (SHA-34), one per
/// development board. `name` is the directory under `benches/` and the package name.
pub const BENCHES: [Example; 2] = [
    Example {
        name: "nrf52840-mldsa",
        target: "thumbv7em-none-eabihf",
        chip: "nRF52840_xxAA",
        hal_feature: "nrf52840",
    },
    Example {
        name: "rp2350-mldsa",
        target: "thumbv8m.main-none-eabihf",
        chip: "RP235x",
        hal_feature: "rp235xa",
    },
];

/// Serialises the tests that run cargo in `benches/<name>/target` (and its
/// `target/mldsa`) against each other within one test binary: cargo unlinks and
/// re-creates `release/<bin>` on every invocation, even a fresh no-op one, so a
/// sibling test reading the ELFs (`elf_sizes.py`, `objdump`) can see them missing
/// (SHA-282). One lock per bench keeps the two boards building in parallel. `cargo
/// test` runs test binaries one at a time, so a process-wide lock is enough (a
/// runner that puts each test in its own process, such as `cargo nextest`, would
/// need a file lock instead). A test that panics while holding it must not poison
/// the others (`--no-fail-fast`).
pub fn bench_target_lock(bench: &Example) -> MutexGuard<'static, ()> {
    static LOCKS: [Mutex<()>; BENCHES.len()] = [const { Mutex::new(()) }; BENCHES.len()];
    let i = BENCHES
        .iter()
        .position(|b| b.name == bench.name)
        .unwrap_or_else(|| panic!("{} is not in BENCHES", bench.name));
    LOCKS[i].lock().unwrap_or_else(PoisonError::into_inner)
}

/// The on-target ML-DSA KAT and benchmark tests in `tests/kat.rs` named in the SHA-34
/// plan (shared with the SHA-47 suite checks).
pub const MLDSA_KAT_ON_TARGET_TESTS: [&str; 5] = [
    "dwt_cycle_counter_present",
    "mldsa44_kat",
    "mldsa65_kat",
    "mldsa44_bench",
    "mldsa65_bench",
];

/// Files the SHA-65 LMS/HSS additions put in every bench project, relative to its
/// directory.
pub const LMS_BENCH_FILES: [&str; 3] = [
    "tests/lms.rs",
    "src/bin/size_lms_baseline.rs",
    "src/bin/size_lms.rs",
];

/// The on-target LMS/HSS tests in `tests/lms.rs` named in the SHA-65 plan.
pub const LMS_ON_TARGET_TESTS: [&str; 3] = [
    "lms_kat",
    "lms_bench",
    "lms_rotation_key_b_verifies_against_a_b_and_fails_against_a",
];

/// The LMS/HSS flash-footprint bins (baseline first).
pub const LMS_SIZE_BINS: [&str; 2] = ["size_lms_baseline", "size_lms"];

/// Peak-stack limit for LMS/HSS verify asserted by `lms_bench` (SHA-65 AC4).
pub const LMS_STACK_LIMIT: u32 = 32_768;

/// Files the SHA-42 image-digest additions put in every bench project, relative to its
/// directory.
pub const DIGEST_BENCH_FILES: [&str; 3] = [
    "tests/image.rs",
    "src/bin/size_digest_baseline.rs",
    "src/bin/size_digest.rs",
];

/// The on-target image-digest tests in `tests/image.rs` named in the SHA-42 plan.
pub const DIGEST_ON_TARGET_TESTS: [&str; 2] =
    ["image_digest_200k_from_flash", "image_digest_bench"];

/// The image-digest flash-footprint bins (baseline first).
pub const DIGEST_SIZE_BINS: [&str; 2] = ["size_digest_baseline", "size_digest"];

/// Peak-stack limit for one 256-byte-chunk digest asserted by `image_digest_bench`
/// (SHA-42).
pub const DIGEST_STACK_LIMIT: u32 = 4096;

/// Files the SHA-46 policy-matrix additions put in every bench project, relative to its
/// directory.
pub const POLICY_BENCH_FILES: [&str; 3] = [
    "tests/policy.rs",
    "src/bin/size_verify_baseline.rs",
    "src/bin/size_verify.rs",
];

/// The on-target tests in `tests/policy.rs`: the policy matrix named in the SHA-46 plan
/// and the hybrid Ed25519 + LMS/HSS verify measurement of SHA-69.
pub const POLICY_ON_TARGET_TESTS: [&str; 2] = ["policy_matrix_from_flash", "hybrid_verify_bench"];

/// The hybrid verify flash-footprint bins (baseline first).
pub const POLICY_SIZE_BINS: [&str; 2] = ["size_verify_baseline", "size_verify"];

/// Files the SHA-44 ML-DSA verify additions put in every bench project, relative to its
/// directory (built only with the bench's `ml-dsa` feature).
pub const MLDSA_VERIFY_BENCH_FILES: [&str; 1] = ["tests/mldsa_verify.rs"];

/// The on-target ML-DSA verify test in `tests/mldsa_verify.rs` named in the SHA-44 plan.
pub const MLDSA_ON_TARGET_TESTS: [&str; 1] = ["mldsa_images_from_flash"];

/// The SHA-37 sample images, the SHA-35 golden MCUboot images, the SHA-42 200 KB image,
/// the SHA-46 policy-matrix images (three signed, eighteen deterministic mutations of
/// the hybrid images), the SHA-44 ML-DSA images (two signed, seventeen mutations) and the
/// SHA-69 hybrid Ed25519 + HSS L=2 image (one signed, four mutations) in
/// `tests/fixtures/images/`, generated by
/// `scripts/gen_image_fixtures.py`, followed by the committed test-key files under
/// `keys/`, the fixed classical signatures under `sigs/` and the SHA-46 on-target index
/// `policy-matrix.bin`. Images under `rejected/` are ones the parser must reject. Every
/// entry is listed with its SHA-256 in `MANIFEST.json`.
pub const IMAGE_FIXTURES: [&str; 65] = [
    "keelsign-lms-m32-h5.bin",
    "keelsign-hss2-m32-h5h5.bin",
    "keelsign-lms-protected-tlvs.bin",
    "keelsign-hybrid-ed25519-lms.bin",
    "keelsign-mldsa44.bin",
    "keelsign-mldsa65.bin",
    "keelsign-dual-pq-invalid.bin",
    "mcuboot-rsa2048.bin",
    "mcuboot-ecdsa-p256.bin",
    "mcuboot-ed25519.bin",
    "mcuboot-ed25519-padded.bin",
    "rejected/mcuboot-ed25519-bigendian.bin",
    "mcuboot-ed25519-200k.bin",
    "keelsign-hybrid-ed25519-mldsa44.bin",
    "keelsign-hybrid-protected-tlvs.bin",
    "keelsign-hybrid-reserved-tlv-protected.bin",
    "keelsign-hybrid-bad-ed25519.bin",
    "keelsign-hybrid-bad-pq.bin",
    "keelsign-hybrid-missing-pq.bin",
    "keelsign-hybrid-missing-key-id.bin",
    "keelsign-hybrid-unpaired-ed25519.bin",
    "keelsign-hybrid-keyhash-only.bin",
    "keelsign-hybrid-two-ed25519.bin",
    "keelsign-hybrid-short-ed25519.bin",
    "keelsign-hybrid-bad-body.bin",
    "keelsign-hybrid-bad-sha256.bin",
    "keelsign-hybrid-no-sha256.bin",
    "keelsign-hybrid-two-sha256.bin",
    "keelsign-hybrid-sha384-only.bin",
    "keelsign-hybrid-sig-pure.bin",
    "keelsign-hybrid-flag-encrypted.bin",
    "keelsign-hybrid-flag-compressed.bin",
    "keelsign-hybrid-flag-non-bootable.bin",
    "keelsign-hybrid-two-sec-cnt.bin",
    "keelsign-mldsa44-protected-tlvs.bin",
    "keelsign-mldsa65-protected-tlvs.bin",
    "keelsign-mldsa44-bad-body.bin",
    "keelsign-mldsa44-bad-body-rehashed.bin",
    "keelsign-mldsa44-bad-protected.bin",
    "keelsign-mldsa44-bad-protected-rehashed.bin",
    "keelsign-mldsa44-bad-sig.bin",
    "keelsign-mldsa44-bad-hint.bin",
    "keelsign-mldsa44-short-sig.bin",
    "keelsign-mldsa44-bad-key-id.bin",
    "keelsign-mldsa44-foreign-sig.bin",
    "keelsign-mldsa65-bad-body-rehashed.bin",
    "keelsign-mldsa65-bad-protected-rehashed.bin",
    "keelsign-mldsa65-bad-sig.bin",
    "keelsign-mldsa65-bad-hint.bin",
    "keelsign-mldsa65-short-sig.bin",
    "keelsign-mldsa65-foreign-sig.bin",
    "keelsign-hybrid-mldsa44-missing-pq.bin",
    "keelsign-hybrid-mldsa44-stripped-pq.bin",
    "keelsign-hybrid-ed25519-hss2.bin",
    "keelsign-hybrid-hss2-bad-ed25519.bin",
    "keelsign-hybrid-hss2-bad-pq.bin",
    "keelsign-hybrid-hss2-bad-top-level.bin",
    "keelsign-hybrid-hss2-missing-pq.bin",
    "keys/ed25519-test-key.pem",
    "keys/ed25519-test-key.spki.der",
    "keys/rsa2048-test-key.pem",
    "keys/ecdsa-p256-test-key.pem",
    "sigs/mcuboot-rsa2048.sig",
    "sigs/mcuboot-ecdsa-p256.sig",
    "policy-matrix.bin",
];

/// The SHA-46 on-target index of the policy matrix in `tests/fixtures/images/`.
pub const POLICY_MATRIX_BIN: &str = "policy-matrix.bin";

/// The SHA-44 ML-DSA test keys in MANIFEST.json `keys` (no key file: the seed and the
/// public key are recorded there), as (manifest key, algorithm).
pub const MLDSA_TEST_KEYS: [(&str, &str); 2] = [
    ("mldsa-test-key:mldsa44", "MlDsa44"),
    ("mldsa-test-key:mldsa65", "MlDsa65"),
];

/// The policy keys of every MANIFEST.json `policy` object (SHA-46), in
/// `Policy::ALL` order.
pub const POLICY_KEYS: [&str; 3] = ["classical_only", "pq_only", "hybrid"];

/// Crates that ship (published or linked into user firmware). None of them may depend on
/// the measurement-only `stack-paint` crate.
pub const SHIPPED_CRATES: [&str; 4] = [
    "keelsign",
    "keelsign-verify",
    "keelsign-embassy",
    "keelsign-ffi",
];

/// Absolute path of the workspace root (two levels above this crate).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must exist")
}

/// The text of the `.github/workflows/ci.yml` job `name` (two-space indented key), up to the next job.
pub fn ci_job(ci: &str, name: &str) -> String {
    let start = ci
        .find(&format!("\n  {name}:"))
        .unwrap_or_else(|| panic!("ci.yml must have a `{name}` job"));
    ci[start + 1..]
        .lines()
        .enumerate()
        .take_while(|(i, line)| {
            let next_job = line.starts_with("  ") && !line.starts_with("   ");
            let top_level = !line.is_empty() && !line.starts_with(' ');
            *i == 0 || !(next_job || top_level)
        })
        .map(|(_, line)| format!("{line}\n"))
        .collect()
}

/// `text` without comments (lines starting with `#`, and ` #…` to the end of a line),
/// whitespace or quotes: harmless reformatting (line breaks, indentation, quoting) does
/// not change it, so checks match key tokens rather than exact layout.
pub fn squash(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                return "";
            }
            match line.find(" #") {
                Some(at) => &line[..at],
                None => line,
            }
        })
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect()
}

/// The text of the job `name` in a workflow: from its `  name:` line up to the next
/// line indented by exactly two spaces (the next job, or a comment before it).
pub fn workflow_job<'a>(workflow: &'a str, name: &str) -> &'a str {
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

/// The steps of a job (from [`workflow_job`]), each squashed: the text from one `- ` item
/// of its `steps:` list to the next.
pub fn job_steps(job: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == "steps:")
        .expect("steps:");
    let indent = lines[start + 1..]
        .iter()
        .find(|l| l.trim_start().starts_with("- "))
        .map(|l| l.len() - l.trim_start().len())
        .expect("a step");
    let mut out: Vec<String> = Vec::new();
    for line in &lines[start + 1..] {
        let is_item =
            line.len() - line.trim_start().len() == indent && line.trim_start().starts_with("- ");
        if is_item {
            out.push(String::new());
        }
        if let Some(step) = out.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    out.iter().map(|s| squash(s)).collect()
}

/// The index of the one step containing every token in `tokens` (squashed).
pub fn step_with(steps: &[String], job: &str, tokens: &[&str]) -> usize {
    let found: Vec<usize> = (0..steps.len())
        .filter(|&i| tokens.iter().all(|t| steps[i].contains(&squash(t))))
        .collect();
    assert_eq!(found.len(), 1, "{job}: steps with {tokens:?}: {found:?}");
    found[0]
}

/// A per-test scratch directory under the system temp dir, unique per process
/// and test name. It is removed when dropped.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(test_name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "keelsign-repo-checks-{}-{}",
            std::process::id(),
            test_name
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `cargo` command run in `dir` with its own `CARGO_TARGET_DIR`, so it does not
/// contend for the build lock of the outer `cargo test`.
pub fn cargo_in(dir: &Path, target_dir: &Path) -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(dir).env("CARGO_TARGET_DIR", target_dir);
    cmd
}

/// Run `cmd`, panicking with its output if it fails; returns stdout.
pub fn run_ok(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn command");
    assert!(
        out.status.success(),
        "command {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        cmd,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout is UTF-8")
}

/// A `python3 <workspace>/scripts/<script>` command run from the workspace root.
pub fn python_script(script: &str) -> Command {
    let root = workspace_root();
    let mut cmd = Command::new("python3");
    cmd.current_dir(&root)
        .arg(root.join("scripts").join(script));
    cmd
}

/// Run `cmd` and return its exit success, stdout and stderr. Panics with a clear message
/// if the program cannot be started (for example `python3` missing from `PATH`).
pub fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap_or_else(|e| {
        panic!(
            "could not start {:?}: {e} (the SHA-34 scripts need `python3` on PATH)",
            cmd.get_program()
        )
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Lowercase hex SHA-256 of `data` (FIPS 180-4), so the fixture checks need no extra
/// dependency.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{BENCHES, bench_target_lock};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Locks `bench` on another thread and reports whether it got the lock within
    /// the timeout, so a wrongly shared lock fails the test instead of hanging it.
    fn locks_from_another_thread(index: usize) -> bool {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _guard = bench_target_lock(&BENCHES[index]);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(30)).is_ok()
    }

    #[test]
    fn bench_target_lock_is_per_bench_and_relockable_after_drop() {
        assert_eq!(BENCHES.len(), 2, "the test pairs the two boards");

        // Holding one bench's lock does not block the other bench.
        let nrf = bench_target_lock(&BENCHES[0]);
        assert!(
            locks_from_another_thread(1),
            "{} must not share {}'s lock",
            BENCHES[1].name,
            BENCHES[0].name
        );
        drop(nrf);

        // After the guard drops, the same bench locks again.
        assert!(
            locks_from_another_thread(0),
            "{} must lock again once its guard drops",
            BENCHES[0].name
        );

        // A test that panics while holding the lock does not poison it.
        let poisoner = thread::spawn(|| {
            let _guard = bench_target_lock(&BENCHES[0]);
            panic!("poison the {} lock on purpose", BENCHES[0].name);
        });
        assert!(poisoner.join().is_err(), "the poisoning thread must panic");
        assert!(
            locks_from_another_thread(0),
            "a poisoned {} lock must still be obtained",
            BENCHES[0].name
        );
    }
}
