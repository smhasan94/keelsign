//! Chooses the on-target LMS/HSS fixture `LMS_TARGET` embeds (SHA-67).
//!
//! By default it is `fixtures/lms-target.bin`. With `KEELSIGN_LMS_TARGET` set to an
//! absolute path, that KSLM v2 file is embedded instead: the on-target check of
//! keelsign-signed images (docs/signing.md, "On-target check") packs them with
//! `scripts/lms_image_kat.py` and builds the bench tests with it. The case count is read
//! from the fixture header and exported as `LMS_KAT_TARGET_CASES` (`TARGET_CASES`).

use std::path::PathBuf;

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=KEELSIGN_LMS_TARGET");
    println!("cargo:rerun-if-changed=build.rs");
    let path = match std::env::var_os("KEELSIGN_LMS_TARGET") {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(format!(
                    "KEELSIGN_LMS_TARGET must be an absolute path, not {}",
                    path.display()
                ));
            }
            path
        }
        _ => {
            let dir =
                std::env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is not set")?;
            PathBuf::from(dir).join("fixtures").join("lms-target.bin")
        }
    };
    let text = path
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))?;
    println!("cargo:rerun-if-changed={text}");
    let bytes = std::fs::read(&path).map_err(|e| format!("read {text}: {e}"))?;
    let header = bytes
        .get(..8)
        .ok_or_else(|| format!("{text} is shorter than a KSLM header"))?;
    let (magic, rest) = header.split_at(4);
    let (version, count) = rest.split_at(2);
    if magic != b"KSLM" || version != 2u16.to_le_bytes() {
        return Err(format!("{text} is not a KSLM version 2 fixture"));
    }
    let count = <[u8; 2]>::try_from(count)
        .map(u16::from_le_bytes)
        .map_err(|_| format!("{text}: truncated header"))?;
    println!("cargo:rustc-env=LMS_KAT_TARGET_FIXTURE={text}");
    println!("cargo:rustc-env=LMS_KAT_TARGET_CASES={count}");
    Ok(())
}
