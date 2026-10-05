//! The no_std lint and `unsafe` rules actually fire (SHA-167).
//!
//! The text checks in `verify_crate.rs` and `deps.rs` only prove that the manifests say
//! the right thing. These tests prove the compiler and clippy reject the code: each case
//! copies the workspace members (plus the image fixtures `policy-kat` embeds) to a
//! scratch directory, appends one probe module to the probed crate's root, runs
//! `cargo clippy --message-format=json` there and checks the diagnostic codes.
//!
//! # Crate classes
//!
//! | Class | Crates | Must reject |
//! |---|---|---|
//! | `NoStd` | `keelsign-verify`, `keelsign-embassy`, `lms-kat`, `policy-kat`, `mldsa-kat` | `panic!`, `.unwrap()`, `.expect()`, slice indexing, `unsafe` (forbid level) |
//! | `NoStdException` | `stack-paint` | the four clippy probes, `unsafe` (deny level) |
//! | `Ffi` | `keelsign-ffi` | the four clippy probes, `unsafe` (deny level) |
//! | `Host` | `keelsign`, `repo-checks` | `unsafe` (forbid level) |
//!
//! Every crate also gets a control probe that must compile cleanly, so a broken probe
//! harness cannot pass by rejecting everything.
//!
//! # Why cases strip the source attribute
//!
//! Each probed crate also says `#![forbid(unsafe_code)]` (or `#![deny(unsafe_code)]`) in
//! its root. Left in place, that attribute would keep the `unsafe` cases failing even if
//! the manifest `[lints]` table were dropped. So every case removes, in its copy only, the
//! crate-level `#![deny(L)]` / `#![forbid(L)]` attribute for the lint `L` under test
//! (single- or multi-line: an inner attribute runs from `#![` to its matching `]`), and
//! fails with "split the attribute" if any other crate-level attribute still names `L`
//! (a combined list or a `cfg_attr`). Each case thus
//! proves the manifest setting alone fires; the source attributes stay covered by the
//! text checks.
//!
//! # Replay hazard
//!
//! All copies share one inner target directory (`CARGO_TARGET_TMPDIR/lint-probes`) so
//! reruns are warm. Copies at different paths map to the same build unit there, and a
//! copy older than the last build would be judged fresh, so cargo would replay another
//! copy's cached diagnostics. Hence the cases run one at a time under a lock, each runs
//! `cargo clean -p <package>` first, and each probe carries a canary
//! (`let keelsign_lint_probe_canary_<case>_<pid> = 0u8;`) that must show up as exactly one
//! `unused_variables` warning, proving this copy was compiled.
//!
//! # Environment limits
//!
//! The inner cargo runs have `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
//! `CARGO_BUILD_RUSTFLAGS`, every `CARGO_TARGET_*_RUSTFLAGS` / `*_RUSTDOCFLAGS`,
//! `CARGO_BUILD_TARGET`, `CLIPPY_CONF_DIR` and the rustc wrapper variables removed. Cargo
//! configuration files are not neutralised: a user-level `~/.cargo/config.toml`
//! `[build] rustflags`, or a `.cargo/config.toml` in a directory above the scratch copy,
//! still applies, and one adding `-D clippy::…` could mask a dropped manifest `[lints]`
//! table for the crates other than `keelsign-verify` (whose mutation test asserts the
//! probes compile without it). A future repository-root `.cargo/config.toml` would not be
//! copied either (dot-directories are skipped).
//!
//! # Manual TP2 procedure (break the inheritance, then revert)
//!
//! 1. `T=<scratch>/tp2-broken; mkdir -p $T && git -C <repo> archive HEAD | tar -x -C $T`
//! 2. Remove the `[lints]` / `workspace = true` lines from `$T/keelsign-verify/Cargo.toml`
//!    with a scripted edit.
//! 3. `cd $T && CARGO_TARGET_DIR=$T/target cargo test -p repo-checks --locked --offline
//!    --test lints --no-fail-fast` and record the failing test names: exactly the seven
//!    `keelsign_verify_rejects_{panic,unwrap,expect,slice_indexing,unsafe}`,
//!    `keelsign_verify_forbids_unsafe_even_with_allow` and
//!    `keelsign_verify_probes_compile_without_lint_inheritance`.
//! 4. Revert (extract a fresh copy) and re-run the same command: every test passes.
//!
//! `CARGO_TARGET_DIR` must point inside the extract. With a target directory shared
//! between checkouts, cargo can reuse a test binary built from another checkout (the
//! tests locate the workspace through `env!("CARGO_MANIFEST_DIR")`), and the "broken" run
//! then silently tests the wrong tree.
//! 5. Optional: set the root `[workspace.lints.rust] unsafe_code = "deny"` instead; exactly
//!    the five `*_forbids_unsafe_even_with_allow` cases of the crates that inherit the
//!    workspace lints fail (`keelsign-verify`, `keelsign-embassy`, `lms-kat`, `policy-kat`,
//!    `mldsa-kat`; the host crates set their own `unsafe_code = "forbid"`).

use repo_checks::{ScratchDir, cargo_in, workspace_root};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// How strictly a workspace member is linted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// `no_std` crate inheriting the workspace lints: four clippy denies, forbid unsafe.
    NoStd,
    /// The measurement-only `stack-paint` crate: four clippy denies, unsafe at deny.
    NoStdException,
    /// The C ABI crate `keelsign-ffi` (SHA-60): four clippy denies, unsafe at deny (its
    /// one `abi` module allows it). `no_std` in its shipped (`panic = "abort"`) builds.
    Ffi,
    /// Host crate: forbid unsafe only.
    Host,
}

/// A workspace member probed by these tests.
struct Crate {
    /// Package name, as passed to `cargo -p`.
    package: &'static str,
    /// Directory relative to the workspace root, as listed in `members`.
    dir: &'static str,
    class: Class,
}

const KEELSIGN_VERIFY: Crate = Crate {
    package: "keelsign-verify",
    dir: "keelsign-verify",
    class: Class::NoStd,
};

const KEELSIGN_EMBASSY: Crate = Crate {
    package: "keelsign-embassy",
    dir: "keelsign-embassy",
    class: Class::NoStd,
};

const LMS_KAT: Crate = Crate {
    package: "lms-kat",
    dir: "benches/lms-kat",
    class: Class::NoStd,
};

const POLICY_KAT: Crate = Crate {
    package: "policy-kat",
    dir: "benches/policy-kat",
    class: Class::NoStd,
};

const MLDSA_KAT: Crate = Crate {
    package: "mldsa-kat",
    dir: "benches/mldsa-kat",
    class: Class::NoStd,
};

const STACK_PAINT: Crate = Crate {
    package: "stack-paint",
    dir: "benches/stack-paint",
    class: Class::NoStdException,
};

const KEELSIGN_FFI: Crate = Crate {
    package: "keelsign-ffi",
    dir: "keelsign-ffi",
    class: Class::Ffi,
};

const KEELSIGN: Crate = Crate {
    package: "keelsign",
    dir: "keelsign",
    class: Class::Host,
};

const REPO_CHECKS: Crate = Crate {
    package: "repo-checks",
    dir: "tools/repo-checks",
    class: Class::Host,
};

/// Every workspace member, classified.
const CRATES: [Crate; 9] = [
    KEELSIGN_VERIFY,
    KEELSIGN_FFI,
    KEELSIGN_EMBASSY,
    LMS_KAT,
    POLICY_KAT,
    MLDSA_KAT,
    STACK_PAINT,
    KEELSIGN,
    REPO_CHECKS,
];

/// One snippet of code appended to a crate root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Control,
    Panic,
    Unwrap,
    Expect,
    SliceIndexing,
    Unsafe,
    UnsafeUnderAllow,
}

const UNSAFE_BODY: &str = "let p: *const u8 = x;\n        \
    // SAFETY: lint probe, never built into a shipped crate.\n        \
    unsafe { *p }";

impl Probe {
    /// The probe module for case `case`, with canary variable `marker`.
    fn snippet(self, case: &str, marker: &str) -> String {
        let (attr, args, ret, body) = match self {
            Probe::Control => ("", "x: u8", " -> u8", "x.wrapping_add(1)"),
            Probe::Panic => ("", "", "", "panic!(\"lint probe\");"),
            Probe::Unwrap => ("", "x: Option<u8>", " -> u8", "x.unwrap()"),
            Probe::Expect => ("", "x: Option<u8>", " -> u8", "x.expect(\"lint probe\")"),
            Probe::SliceIndexing => ("", "x: &[u8], i: usize", " -> u8", "x[i]"),
            Probe::Unsafe => ("", "x: &u8", " -> u8", UNSAFE_BODY),
            Probe::UnsafeUnderAllow => ("#[allow(unsafe_code)]\n", "x: &u8", " -> u8", UNSAFE_BODY),
        };
        format!(
            "{attr}#[allow(dead_code)]\n\
             mod keelsign_lint_probe_{case} {{\n    \
                 pub(crate) fn probe({args}){ret} {{\n        \
                     let {marker} = 0u8;\n        \
                     {body}\n    \
                 }}\n\
             }}\n"
        )
    }

    /// Diagnostic codes that must be reported at `error` level.
    fn expected(self) -> &'static [&'static str] {
        match self {
            Probe::Control => &[],
            Probe::Panic => &["clippy::panic"],
            Probe::Unwrap => &["clippy::unwrap_used"],
            Probe::Expect => &["clippy::expect_used"],
            Probe::SliceIndexing => &["clippy::indexing_slicing"],
            Probe::Unsafe | Probe::UnsafeUnderAllow => &["unsafe_code"],
        }
    }

    /// Error codes that may appear besides the expected ones.
    fn tolerated(self) -> &'static [&'static str] {
        match self {
            // `#[allow(unsafe_code)]` under `forbid` is itself an error.
            Probe::UnsafeUnderAllow => &["E0453"],
            _ => &[],
        }
    }

    /// The lint whose crate-root `#![deny]` / `#![forbid]` line the case strips.
    fn stripped_lint(self) -> Option<&'static str> {
        self.expected().first().copied()
    }
}

/// Extra manifest edit applied to the probed crate's copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Edit {
    None,
    /// Remove `[lints]\nworkspace = true\n` from the probed crate's `Cargo.toml`.
    DropLintInheritance,
}

/// One compiler diagnostic, located by its primary span.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Diag {
    level: String,
    code: Option<String>,
    file: Option<String>,
    line: Option<u64>,
    text: String,
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] {}:{}: {}",
            self.level,
            self.code.as_deref().unwrap_or("-"),
            self.file.as_deref().unwrap_or("-"),
            self.line.map_or_else(|| "-".to_owned(), |l| l.to_string()),
            self.text
        )
    }
}

/// The result of one clippy run on a probed copy.
struct Outcome {
    case: String,
    command: String,
    success: bool,
    diags: Vec<Diag>,
    stderr: String,
    /// Crate root relative to the copy's workspace root, as spans report it.
    root_rel: String,
    /// 1-based line of the first appended probe line.
    first_probe_line: u64,
    /// Canary variable names, one per appended probe.
    markers: Vec<String>,
}

impl Outcome {
    /// A failure report naming the case and command, listing every diagnostic and the
    /// tail of stderr.
    fn report(&self, problem: &str) -> String {
        let diags: Vec<String> = self.diags.iter().map(|d| format!("  {d}")).collect();
        format!(
            "case `{}`: {problem}\ncommand: {}\nexit success: {}\ncrate root: {} (probes from line {})\ndiagnostics:\n{}\nstderr (last 40 lines):\n{}",
            self.case,
            self.command,
            self.success,
            self.root_rel,
            self.first_probe_line,
            diags.join("\n"),
            tail(&self.stderr, 40)
        )
    }

    /// Check the outcome against the expected and tolerated error codes.
    fn check(&self, expected: &[&str], tolerated: &[&str]) {
        for marker in &self.markers {
            let hits = self
                .diags
                .iter()
                .filter(|d| {
                    d.code.as_deref() == Some("unused_variables") && d.text.contains(marker)
                })
                .count();
            assert_eq!(
                hits,
                1,
                "{}",
                self.report(&format!(
                    "canary `{marker}` must be reported exactly once (got {hits}); \
                     was this copy compiled?"
                ))
            );
        }
        let errors: Vec<&Diag> = self.diags.iter().filter(|d| d.level == "error").collect();
        for code in expected {
            assert!(
                errors.iter().any(|d| d.code.as_deref() == Some(*code)),
                "{}",
                self.report(&format!("expected an error with code `{code}`"))
            );
        }
        for d in &errors {
            let code = d.code.as_deref().unwrap_or("-");
            assert!(
                expected.contains(&code) || tolerated.contains(&code),
                "{}",
                self.report(&format!("unexpected error code `{code}`"))
            );
            assert!(
                d.file.as_deref() == Some(self.root_rel.as_str())
                    && d.line.is_some_and(|l| l >= self.first_probe_line),
                "{}",
                self.report(&format!("error outside the probe lines: {d}"))
            );
        }
        assert_eq!(
            self.success,
            expected.is_empty(),
            "{}",
            self.report("clippy exit status must be success iff no error is expected")
        );
    }
}

/// Serialises the cases: they share one inner target directory.
static PROBE_LOCK: Mutex<()> = Mutex::new(());

/// `cargo clippy --version`, checked once.
static CLIPPY: OnceLock<Result<String, String>> = OnceLock::new();

/// Environment variables that would change how the probes compile.
const SCRUBBED_ENV: [&str; 8] = [
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_TARGET",
    "CLIPPY_CONF_DIR",
];

/// Whether an environment variable is a per-target flags override
/// (`CARGO_TARGET_<triple>_RUSTFLAGS` / `_RUSTDOCFLAGS`).
fn is_target_flags_var(name: &str) -> bool {
    name.starts_with("CARGO_TARGET_")
        && (name.ends_with("_RUSTFLAGS") || name.ends_with("_RUSTDOCFLAGS"))
}

/// Non-member directories the members compile against: `policy-kat` embeds the image
/// fixtures with `include_bytes!("../../../tests/fixtures/images/…")`.
const NON_MEMBER_INPUTS: [&str; 1] = ["tests/fixtures/images"];

/// The inner target directory shared by every case.
fn probe_target_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("lint-probes")
}

/// The `members = [ … ]` entries of the root `Cargo.toml`.
///
/// Anchored on a line whose trimmed text starts with `members` (so `default-members` does
/// not match); `#` comments inside the array are ignored.
fn workspace_members(root_manifest: &str) -> Vec<String> {
    let mut lines = root_manifest.lines().skip_while(|l| {
        !l.trim_start()
            .strip_prefix("members")
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    });
    let mut list = String::new();
    for line in lines.by_ref() {
        let code = line.split('#').next().unwrap_or_default();
        list.push_str(code);
        list.push('\n');
        if code.contains(']') {
            break;
        }
    }
    let start = list.find('[').expect("root Cargo.toml has `members = [`");
    let end = list.rfind(']').expect("`members` list is closed");
    assert!(start < end, "`members` list is closed");
    list[start + 1..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Copy `src` to `dst` recursively, skipping `target` and dot-directories.
fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|e| panic!("create {}: {e}", dst.display()));
    let entries = fs::read_dir(src).unwrap_or_else(|e| panic!("list {}: {e}", src.display()));
    for entry in entries {
        let entry = entry.expect("read dir entry");
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name.starts_with('.') {
                continue;
            }
            copy_tree(&path, &dst.join(&*name));
        } else if path.is_file() {
            fs::copy(&path, dst.join(&*name))
                .unwrap_or_else(|e| panic!("copy {}: {e}", path.display()));
        }
    }
}

/// The crate root of a member directory and the cargo target-selection flag for it:
/// `src/lib.rs` (`--lib`) if present, else `src/main.rs` (`--bins`).
fn crate_root(member_dir: &Path) -> (&'static str, &'static str) {
    if member_dir.join("src/lib.rs").is_file() {
        ("src/lib.rs", "--lib")
    } else if member_dir.join("src/main.rs").is_file() {
        ("src/main.rs", "--bins")
    } else {
        panic!(
            "{} has neither src/lib.rs nor src/main.rs",
            member_dir.display()
        )
    }
}

/// A crate-level inner attribute: its text from `#![` to the matching `]` (joined across
/// lines) and the 0-based lines it spans.
#[derive(Debug, PartialEq, Eq)]
struct InnerAttr {
    text: String,
    first_line: usize,
    last_line: usize,
}

impl InnerAttr {
    /// Whether one of the attribute's tokens is `name` (a lint, `no_std`, …).
    fn names(&self, name: &str) -> bool {
        self.text
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .any(|token| token == name)
    }
}

/// Every inner attribute (`#![…]`) that starts a line of `text`, tracking bracket depth
/// across lines and skipping string literals and `//` comments.
fn inner_attributes(text: &str) -> Vec<InnerAttr> {
    let lines: Vec<&str> = text.lines().collect();
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if !trimmed.starts_with("#![") {
            i += 1;
            continue;
        }
        let start = lines[i].len() - trimmed.len();
        let first_line = i;
        let mut text = String::new();
        let mut depth = 0usize;
        let mut in_str = false;
        let mut escaped = false;
        let mut col = start;
        'scan: while i < lines.len() {
            let line = &lines[i][col..];
            let mut chars = line.char_indices().peekable();
            while let Some((pos, c)) = chars.next() {
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match c {
                    '"' => in_str = true,
                    '/' if chars.peek().is_some_and(|&(_, n)| n == '/') => break,
                    '[' => depth += 1,
                    ']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            text.push_str(&line[..=pos]);
                            break 'scan;
                        }
                    }
                    _ => {}
                }
            }
            text.push_str(line);
            text.push('\n');
            i += 1;
            col = 0;
        }
        attrs.push(InnerAttr {
            text,
            first_line,
            last_line: i.min(lines.len().saturating_sub(1)),
        });
        i += 1;
    }
    attrs
}

/// Remove the crate-level `#![deny(lint)]` / `#![forbid(lint)]` attribute from `text`
/// (single- or multi-line). Errs if another crate-level attribute still names `lint`
/// (a combined list or a `cfg_attr`).
fn strip_lint_attribute(text: &str, lint: &str) -> Result<String, String> {
    let lone: Vec<String> = ["deny", "forbid"]
        .iter()
        .flat_map(|level| {
            [
                format!("#![{level}({lint})]"),
                format!("#![{level}({lint},)]"),
            ]
        })
        .collect();
    let mut drop = vec![false; text.lines().count()];
    for attr in inner_attributes(text) {
        if !attr.names(lint) {
            continue;
        }
        let compact: String = attr.text.chars().filter(|c| !c.is_whitespace()).collect();
        if !lone.contains(&compact) {
            return Err(format!(
                "`{}` names `{lint}` alongside other items; split the attribute so the lint \
                 has an attribute of its own",
                attr.text.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        }
        for flag in &mut drop[attr.first_line..=attr.last_line] {
            *flag = true;
        }
    }
    let mut out: String = text
        .lines()
        .zip(&drop)
        .filter(|(_, d)| !**d)
        .map(|(l, _)| format!("{l}\n"))
        .collect();
    if out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

/// The last `n` lines of `text`.
fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn check_clippy_installed() {
    let version = CLIPPY.get_or_init(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        match std::process::Command::new(&cargo)
            .args(["clippy", "--version"])
            .output()
        {
            Ok(out) if out.status.success() => {
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            }
            Ok(out) => Err(String::from_utf8_lossy(&out.stderr).into_owned()),
            Err(e) => Err(e.to_string()),
        }
    });
    if let Err(e) = version {
        panic!(
            "`cargo clippy --version` failed; install the clippy component \
             (`rustup component add clippy`): {e}"
        );
    }
}

/// Copy the workspace members, append `probes` to `krate`'s root, apply `edit`, and run
/// clippy on the copy.
fn run_case(case: &str, krate: &Crate, probes: &[Probe], edit: Edit) -> Outcome {
    let _guard = PROBE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    check_clippy_installed();

    let root = workspace_root();
    let root_manifest = read(&root.join("Cargo.toml"));
    let members = workspace_members(&root_manifest);
    assert!(
        members.iter().any(|m| m == krate.dir),
        "{} is not a workspace member",
        krate.dir
    );

    let scratch = ScratchDir::new(&format!("lints-{case}"));
    let copy = scratch.path().join("ws");
    fs::create_dir_all(&copy).expect("create copy dir");
    for file in ["Cargo.toml", "Cargo.lock"] {
        fs::copy(root.join(file), copy.join(file)).unwrap_or_else(|e| panic!("copy {file}: {e}"));
    }
    for dir in members.iter().map(String::as_str).chain(NON_MEMBER_INPUTS) {
        copy_tree(&root.join(dir), &copy.join(dir));
    }

    let member_dir = copy.join(krate.dir);
    let (root_file, target_flag) = crate_root(&member_dir);
    let root_rel = format!("{}/{root_file}", krate.dir);
    let root_path = member_dir.join(root_file);

    let mut text = read(&root_path);
    for lint in probes.iter().filter_map(|p| p.stripped_lint()) {
        text = strip_lint_attribute(&text, lint)
            .unwrap_or_else(|e| panic!("case `{case}`: {root_rel}: {e}"));
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let first_probe_line = u64::try_from(text.lines().count() + 1).expect("line count fits");
    let mut markers = Vec::new();
    for (i, probe) in probes.iter().enumerate() {
        let probe_case = if probes.len() == 1 {
            case.to_owned()
        } else {
            format!("{case}_{i}")
        };
        let marker = format!(
            "keelsign_lint_probe_canary_{probe_case}_{}",
            std::process::id()
        );
        text.push_str(&probe.snippet(&probe_case, &marker));
        markers.push(marker);
    }
    write(&root_path, &text);

    if edit == Edit::DropLintInheritance {
        let manifest_path = member_dir.join("Cargo.toml");
        let manifest = read(&manifest_path);
        let inherit = "[lints]\nworkspace = true\n";
        assert!(
            manifest.contains(inherit),
            "{}/Cargo.toml must contain `[lints]\\nworkspace = true` before the mutation",
            krate.dir
        );
        write(&manifest_path, &manifest.replacen(inherit, "", 1));
    }

    let target_dir = probe_target_dir();
    let cargo = |args: &[&str]| {
        let mut cmd = cargo_in(&copy, &target_dir);
        for var in SCRUBBED_ENV {
            cmd.env_remove(var);
        }
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(is_target_flags_var) {
                cmd.env_remove(name);
            }
        }
        cmd.args(args);
        cmd.output()
            .unwrap_or_else(|e| panic!("spawn cargo {}: {e}", args.join(" ")))
    };

    let clean = cargo(&["clean", "-p", krate.package, "--locked", "--offline"]);
    assert!(
        clean.status.success(),
        "case `{case}`: cargo clean -p {} failed:\n{}",
        krate.package,
        String::from_utf8_lossy(&clean.stderr)
    );

    let args = [
        "clippy",
        "-p",
        krate.package,
        target_flag,
        "--locked",
        "--offline",
        "--message-format=json",
    ];
    let command = format!("cargo {} (in {})", args.join(" "), copy.display());
    let out = cargo(&args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let mut diags = Vec::new();
    let mut compiler_messages = 0usize;
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let parsed = parse_message(line)
            .unwrap_or_else(|e| panic!("case `{case}`: unparsable cargo message ({e}): {line}"));
        if let Some(message) = parsed {
            compiler_messages += 1;
            diags.extend(message);
        }
    }
    if !out.status.success() && compiler_messages == 0 {
        panic!(
            "case `{case}`: {command} failed without compiler messages; \
             run `cargo fetch --locked` if crates are missing\nstderr (last 40 lines):\n{}",
            tail(&stderr, 40)
        );
    }

    Outcome {
        case: case.to_owned(),
        command,
        success: out.status.success(),
        diags,
        stderr,
        root_rel,
        first_probe_line,
        markers,
    }
}

/// Run one probe against `krate` and check the expected codes.
fn check_case(case: &str, krate: &Crate, probe: Probe) {
    let applicable = match krate.class {
        Class::NoStd => true,
        Class::NoStdException | Class::Ffi => probe != Probe::UnsafeUnderAllow,
        Class::Host => matches!(
            probe,
            Probe::Control | Probe::Unsafe | Probe::UnsafeUnderAllow
        ),
    };
    assert!(
        applicable,
        "probe {probe:?} does not apply to {} ({:?})",
        krate.package, krate.class
    );
    run_case(case, krate, &[probe], Edit::None).check(probe.expected(), probe.tolerated());
}

macro_rules! probe_cases {
    ($krate:expr; $($name:ident => $probe:ident,)*) => {
        $(
            #[test]
            fn $name() {
                check_case(stringify!($name), &$krate, Probe::$probe);
            }
        )*
    };
}

probe_cases! { KEELSIGN_VERIFY;
    keelsign_verify_probe_control_is_clean => Control,
    keelsign_verify_rejects_panic => Panic,
    keelsign_verify_rejects_unwrap => Unwrap,
    keelsign_verify_rejects_expect => Expect,
    keelsign_verify_rejects_slice_indexing => SliceIndexing,
    keelsign_verify_rejects_unsafe => Unsafe,
    keelsign_verify_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

probe_cases! { KEELSIGN_EMBASSY;
    keelsign_embassy_probe_control_is_clean => Control,
    keelsign_embassy_rejects_panic => Panic,
    keelsign_embassy_rejects_unwrap => Unwrap,
    keelsign_embassy_rejects_expect => Expect,
    keelsign_embassy_rejects_slice_indexing => SliceIndexing,
    keelsign_embassy_rejects_unsafe => Unsafe,
    keelsign_embassy_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

probe_cases! { LMS_KAT;
    lms_kat_probe_control_is_clean => Control,
    lms_kat_rejects_panic => Panic,
    lms_kat_rejects_unwrap => Unwrap,
    lms_kat_rejects_expect => Expect,
    lms_kat_rejects_slice_indexing => SliceIndexing,
    lms_kat_rejects_unsafe => Unsafe,
    lms_kat_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

probe_cases! { POLICY_KAT;
    policy_kat_probe_control_is_clean => Control,
    policy_kat_rejects_panic => Panic,
    policy_kat_rejects_unwrap => Unwrap,
    policy_kat_rejects_expect => Expect,
    policy_kat_rejects_slice_indexing => SliceIndexing,
    policy_kat_rejects_unsafe => Unsafe,
    policy_kat_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

probe_cases! { MLDSA_KAT;
    mldsa_kat_probe_control_is_clean => Control,
    mldsa_kat_rejects_panic => Panic,
    mldsa_kat_rejects_unwrap => Unwrap,
    mldsa_kat_rejects_expect => Expect,
    mldsa_kat_rejects_slice_indexing => SliceIndexing,
    mldsa_kat_rejects_unsafe => Unsafe,
    mldsa_kat_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

// `stack-paint` denies (not forbids) unsafe_code so its one Arm-only module can allow it;
// there is no forbid-level case.
probe_cases! { STACK_PAINT;
    stack_paint_probe_control_is_clean => Control,
    stack_paint_rejects_panic => Panic,
    stack_paint_rejects_unwrap => Unwrap,
    stack_paint_rejects_expect => Expect,
    stack_paint_rejects_slice_indexing => SliceIndexing,
    stack_paint_rejects_unsafe => Unsafe,
}

// `keelsign-ffi` denies (not forbids) unsafe_code so its one `abi` module can allow it.
probe_cases! { KEELSIGN_FFI;
    keelsign_ffi_probe_control_is_clean => Control,
    keelsign_ffi_rejects_panic => Panic,
    keelsign_ffi_rejects_unwrap => Unwrap,
    keelsign_ffi_rejects_expect => Expect,
    keelsign_ffi_rejects_slice_indexing => SliceIndexing,
    keelsign_ffi_rejects_unsafe => Unsafe,
}

probe_cases! { KEELSIGN;
    keelsign_probe_control_is_clean => Control,
    keelsign_rejects_unsafe => Unsafe,
    keelsign_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

probe_cases! { REPO_CHECKS;
    repo_checks_probe_control_is_clean => Control,
    repo_checks_rejects_unsafe => Unsafe,
    repo_checks_forbids_unsafe_even_with_allow => UnsafeUnderAllow,
}

/// Every workspace member has a class (so it gets probed), and every `no_std` member is
/// probed as `NoStd` or is one of the two `unsafe` exceptions, `stack-paint` and
/// `keelsign-ffi` (CLAUDE.md).
#[test]
fn every_workspace_member_is_classified() {
    let root = workspace_root();
    let mut members = workspace_members(&read(&root.join("Cargo.toml")));
    for member in &members {
        assert!(
            CRATES.iter().any(|c| c.dir == member),
            "workspace member `{member}` is not classified in tests/lints.rs `CRATES`; \
             add it with its class so its lint rules are probed"
        );
    }
    let mut classified: Vec<String> = CRATES.iter().map(|c| c.dir.to_owned()).collect();
    members.sort();
    classified.sort();
    assert_eq!(
        classified, members,
        "tests/lints.rs `CRATES` must list exactly the workspace members"
    );

    let exceptions: Vec<&str> = CRATES
        .iter()
        .filter(|c| matches!(c.class, Class::NoStdException | Class::Ffi))
        .map(|c| c.dir)
        .collect();
    assert_eq!(
        exceptions,
        ["keelsign-ffi", "benches/stack-paint"],
        "keelsign-ffi and stack-paint are the only crates allowed to deny rather than \
         forbid unsafe_code"
    );

    for krate in &CRATES {
        let dir = root.join(krate.dir);
        let (root_file, _) = crate_root(&dir);
        let is_no_std = inner_attributes(&read(&dir.join(root_file)))
            .iter()
            .any(|a| a.names("no_std"));
        assert!(
            !is_no_std
                || matches!(
                    krate.class,
                    Class::NoStd | Class::NoStdException | Class::Ffi
                ),
            "{} is `#![no_std]` but classified {:?}; classify it NoStd so the no_std lint \
             probes run against it",
            krate.dir,
            krate.class
        );
    }
}

/// AC1, automated half of TP2: without `[lints] workspace = true` (and with the source
/// attribute stripped) every probe compiles, so the rejections above come from the
/// manifest lints.
#[test]
fn keelsign_verify_probes_compile_without_lint_inheritance() {
    let probes = [
        Probe::Panic,
        Probe::Unwrap,
        Probe::Expect,
        Probe::SliceIndexing,
        Probe::Unsafe,
    ];
    let outcome = run_case(
        "keelsign_verify_probes_compile_without_lint_inheritance",
        &KEELSIGN_VERIFY,
        &probes,
        Edit::DropLintInheritance,
    );
    assert_eq!(outcome.markers.len(), probes.len());
    outcome.check(&[], &[]);
}

// ---------------------------------------------------------------------------------------
// A minimal JSON reader for cargo's `--message-format=json` lines (no dependencies).

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }
}

struct JsonReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl JsonReader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, String> {
        let b = self.peek().ok_or("unexpected end of input")?;
        self.pos += 1;
        Ok(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        let got = self.next()?;
        if got == b {
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at byte {}, found `{}`",
                b as char,
                self.pos - 1,
                got as char
            ))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        for b in word.bytes() {
            self.expect(b)?;
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek().ok_or("unexpected end of input")? {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.skip_ws();
                    let key = self.string()?;
                    self.skip_ws();
                    self.expect(b':')?;
                    fields.push((key, self.value()?));
                    self.skip_ws();
                    match self.next()? {
                        b',' => continue,
                        b'}' => return Ok(Json::Obj(fields)),
                        b => return Err(format!("expected `,` or `}}`, found `{}`", b as char)),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.next()? {
                        b',' => continue,
                        b']' => return Ok(Json::Arr(items)),
                        b => return Err(format!("expected `,` or `]`, found `{}`", b as char)),
                    }
                }
            }
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal("true", Json::Bool(true)),
            b'f' => self.literal("false", Json::Bool(false)),
            b'n' => self.literal("null", Json::Null),
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.pos += 1;
                }
                let num =
                    std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
                Ok(Json::Num(num.to_owned()))
            }
            b => Err(format!("unexpected `{}` at byte {}", b as char, self.pos)),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let digit = (self.next()? as char)
                .to_digit(16)
                .ok_or("bad \\u escape")?;
            v = v * 16 + digit;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                b'"' => return String::from_utf8(out).map_err(|e| e.to_string()),
                b'\\' => {
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let lo = self.hex4()?;
                                0x10000 + ((hi - 0xD800) << 10) + (lo.wrapping_sub(0xDC00) & 0x3FF)
                            } else {
                                hi
                            };
                            char::from_u32(code).ok_or("bad \\u code point")?
                        }
                        b => return Err(format!("bad escape `\\{}`", b as char)),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                b => out.push(b),
            }
        }
    }
}

fn parse_json(text: &str) -> Result<Json, String> {
    let mut reader = JsonReader {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = reader.value()?;
    reader.skip_ws();
    if reader.pos != reader.bytes.len() {
        return Err(format!("trailing data at byte {}", reader.pos));
    }
    Ok(value)
}

/// Parse one cargo JSON message line. `Ok(None)`: not a compiler message.
/// `Ok(Some(None))`: a compiler message that is not a located diagnostic (failure notes,
/// code-less and span-less summaries such as "aborting due to …").
fn parse_message(line: &str) -> Result<Option<Option<Diag>>, String> {
    let value = parse_json(line)?;
    if value.get("reason").and_then(Json::as_str) != Some("compiler-message") {
        return Ok(None);
    }
    let message = value
        .get("message")
        .ok_or("compiler-message without `message`")?;
    let level = message
        .get("level")
        .and_then(Json::as_str)
        .ok_or("message without `level`")?;
    if level == "failure-note" {
        return Ok(Some(None));
    }
    let code = message
        .get("code")
        .and_then(|c| c.get("code"))
        .and_then(Json::as_str)
        .map(str::to_owned);
    let primary = message
        .get("spans")
        .and_then(Json::as_array)
        .and_then(|spans| {
            spans
                .iter()
                .find(|s| s.get("is_primary") == Some(&Json::Bool(true)))
        });
    if code.is_none() && primary.is_none() {
        return Ok(Some(None));
    }
    Ok(Some(Some(Diag {
        level: level.to_owned(),
        code,
        file: primary
            .and_then(|s| s.get("file_name"))
            .and_then(Json::as_str)
            .map(str::to_owned),
        line: primary
            .and_then(|s| s.get("line_start"))
            .and_then(Json::as_u64),
        text: message
            .get("message")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned(),
    })))
}

#[test]
fn diagnostic_parser_reads_codes_levels_and_spans() {
    // A real clippy 0.1.91 (rustc 1.91.1) line from `--message-format=json-diagnostic-
    // rendered-ansi`, with the scratch path shortened to `/w`. It carries `\"`, `\n` and
    // `\u001b` escapes.
    let panic_line = r#"{"reason":"compiler-message","package_id":"path+file:///w/canned#0.0.0","manifest_path":"/w/canned/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"canned","src_path":"/w/canned/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"message":{"$message_type":"diagnostic","message":"`panic` should not be present in production code","code":{"code":"clippy::panic","explanation":null},"level":"error","spans":[{"file_name":"src/lib.rs","byte_start":17,"byte_end":37,"line_start":2,"line_end":2,"column_start":5,"column_end":25,"is_primary":true,"text":[{"text":"    panic!(\"lint probe\");","highlight_start":5,"highlight_end":25}],"label":null,"suggested_replacement":null,"suggestion_applicability":null,"expansion":null}],"children":[{"message":"for further information visit https://rust-lang.github.io/rust-clippy/rust-1.91.0/index.html#panic","code":null,"level":"help","spans":[],"children":[],"rendered":null},{"message":"requested on the command line with `-D clippy::panic`","code":null,"level":"note","spans":[],"children":[],"rendered":null}],"rendered":"\u001b[0m\u001b[1m\u001b[38;5;9merror\u001b[0m\u001b[0m\u001b[1m: `panic` should not be present in production code\u001b[0m\n\u001b[0m \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m--> \u001b[0m\u001b[0msrc/lib.rs:2:5\u001b[0m\n\u001b[0m  \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m|\u001b[0m\n\u001b[0m\u001b[1m\u001b[38;5;12m2\u001b[0m\u001b[0m \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m|\u001b[0m\u001b[0m \u001b[0m\u001b[0m    panic!(\"lint probe\");\u001b[0m\n\u001b[0m  \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m|\u001b[0m\u001b[0m     \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;9m^^^^^^^^^^^^^^^^^^^^\u001b[0m\n\u001b[0m  \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m|\u001b[0m\n\u001b[0m  \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m= \u001b[0m\u001b[0m\u001b[1mhelp\u001b[0m\u001b[0m: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.91.0/index.html#panic\u001b[0m\n\u001b[0m  \u001b[0m\u001b[0m\u001b[1m\u001b[38;5;12m= \u001b[0m\u001b[0m\u001b[1mnote\u001b[0m\u001b[0m: requested on the command line with `-D clippy::panic`\u001b[0m\n\n"}}"#;
    assert_eq!(
        parse_message(panic_line),
        Ok(Some(Some(Diag {
            level: "error".to_owned(),
            code: Some("clippy::panic".to_owned()),
            file: Some("src/lib.rs".to_owned()),
            line: Some(2),
            text: "`panic` should not be present in production code".to_owned(),
        })))
    );
    let rendered = parse_json(panic_line)
        .ok()
        .and_then(|v| {
            v.get("message")?
                .get("rendered")?
                .as_str()
                .map(str::to_owned)
        })
        .expect("rendered text");
    assert!(rendered.starts_with("\u{1b}[0m\u{1b}[1m\u{1b}[38;5;9merror"));
    assert!(rendered.contains("panic!(\"lint probe\");"));
    assert!(rendered.ends_with("\n\n"));

    assert_eq!(
        parse_message(r#"{"reason":"build-finished","success":false}"#),
        Ok(None)
    );

    let failure_note = r#"{"reason":"compiler-message","package_id":"path+file:///w/canned#0.0.0","manifest_path":"/w/canned/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"canned","src_path":"/w/canned/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"message":{"rendered":"For more information about this error, try `rustc --explain E0453`.\n","$message_type":"diagnostic","children":[],"code":null,"level":"failure-note","message":"For more information about this error, try `rustc --explain E0453`.","spans":[]}}"#;
    assert_eq!(parse_message(failure_note), Ok(Some(None)));

    let aborting = r#"{"reason":"compiler-message","message":{"code":null,"level":"error","message":"aborting due to 2 previous errors","spans":[],"children":[],"rendered":"error: aborting due to 2 previous errors\n\n"}}"#;
    assert_eq!(parse_message(aborting), Ok(Some(None)));

    assert_eq!(
        parse_json(r#"{"a":[1,-2.5e3,true,null,"\u00e9\ud83d\ude00"]}"#),
        Ok(Json::Obj(vec![(
            "a".to_owned(),
            Json::Arr(vec![
                Json::Num("1".to_owned()),
                Json::Num("-2.5e3".to_owned()),
                Json::Bool(true),
                Json::Null,
                Json::Str("\u{e9}\u{1f600}".to_owned()),
            ])
        )]))
    );
    assert!(parse_json(r#"{"a":1"#).is_err());
    assert!(parse_json(r#"{"a":1} x"#).is_err());
}

#[test]
fn crate_attribute_scanner_handles_single_multi_combined_and_cfg_attr() {
    // Single-line attribute of its own: stripped, other attributes kept.
    assert_eq!(
        strip_lint_attribute(
            "#![no_std]\n#![forbid(unsafe_code)]\n#![deny(missing_docs)]\nfn a() {}\n",
            "unsafe_code"
        ),
        Ok("#![no_std]\n#![deny(missing_docs)]\nfn a() {}\n".to_owned())
    );
    // rustfmt-wrapped multi-line attribute of its own: stripped as a whole.
    assert_eq!(
        strip_lint_attribute(
            "#![no_std]\n#![forbid(\n    unsafe_code,\n)]\nfn a() {}\n",
            "unsafe_code"
        ),
        Ok("#![no_std]\nfn a() {}\n".to_owned())
    );
    // Nothing names the lint: unchanged.
    assert_eq!(
        strip_lint_attribute("#![no_std]\nfn a() {}\n", "clippy::panic"),
        Ok("#![no_std]\nfn a() {}\n".to_owned())
    );
    // Combined (single- and multi-line) and `cfg_attr` forms: "split the attribute".
    for combined in [
        "#![forbid(unsafe_code, missing_docs)]\n",
        "#![deny(\n    missing_docs,\n    unsafe_code,\n)]\nfn a() {}\n",
        "#![cfg_attr(not(test), forbid(unsafe_code))]\n",
        "#![cfg_attr(\n    not(test),\n    forbid(unsafe_code)\n)]\n",
    ] {
        let err = strip_lint_attribute(combined, "unsafe_code").expect_err(combined);
        assert!(err.contains("split the attribute"), "{err}");
    }

    // The scanner finds `no_std` in every form the guard must recognise.
    for no_std in [
        "#![no_std]\n",
        "#![no_std] // a comment ]\n",
        "#![cfg_attr(not(test), no_std)]\n",
        "//! Doc.\n#![cfg_attr(\n    not(test),\n    no_std\n)]\n",
    ] {
        assert!(
            inner_attributes(no_std).iter().any(|a| a.names("no_std")),
            "{no_std:?}"
        );
    }
    assert!(
        !inner_attributes("#![forbid(unsafe_code)]\nfn no_std() {}\n")
            .iter()
            .any(|a| a.names("no_std"))
    );
    // Strings with brackets do not end an attribute early.
    assert_eq!(
        inner_attributes("#![doc = \"]\"]\n#![no_std]\n"),
        vec![
            InnerAttr {
                text: "#![doc = \"]\"]".to_owned(),
                first_line: 0,
                last_line: 0,
            },
            InnerAttr {
                text: "#![no_std]".to_owned(),
                first_line: 1,
                last_line: 1,
            },
        ]
    );
}

#[test]
fn workspace_members_ignores_default_members_and_comments() {
    let manifest = "[workspace]\ndefault-members = [\"a\"]\nmembers = [\n    \"a\", # first\n    # \"commented\",\n    \"b/c\",\n]\nexclude = [\"x\"]\n";
    assert_eq!(workspace_members(manifest), ["a", "b/c"]);
    assert_eq!(
        workspace_members("[workspace]\nmembers = [\"one\", \"two\"]\n"),
        ["one", "two"]
    );
    assert!(is_target_flags_var(
        "CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS"
    ));
    assert!(is_target_flags_var(
        "CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTDOCFLAGS"
    ));
    assert!(!is_target_flags_var("CARGO_TARGET_DIR"));
}
