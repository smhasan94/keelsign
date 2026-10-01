//! The keelsign fuzz harness (SHA-39): what the `parse_image` fuzz target checks on
//! every input, as a library so that the same checks run as ordinary tests on stable.
//!
//! [`check_parse_image`] is differential. It runs the parser under test
//! (`keelsign_verify::image`) and an independent reference parser ([`oracle`]) on the
//! same bytes and panics, which libFuzzer reports as a crash, when they disagree or when
//! a parsed image breaks an invariant. A no-panic harness alone could never find a parser
//! that accepts a bad image without crashing (the parser reads only through checked
//! slicing); comparing against the reference parser does.
//!
//! The [`cov`] functions sort each outcome into one match arm per TLV kind and error
//! variant. Each arm carries a `// cov:` marker, and `scripts/fuzz_coverage_check.py`
//! asserts that `cargo fuzz coverage` over the committed corpus reaches every one
//! (docs/fuzzing.md, TP2).
#![forbid(unsafe_code)]

pub mod oracle;
#[cfg(test)]
mod test_util;

use keelsign_verify::Error;
use keelsign_verify::image::{
    Header, IMAGE_HEADER_SIZE, IMAGE_MAGIC, Image, ParseError, RawHeader, TLV_HEADER_SIZE,
    TLV_INFO_MAGIC, TLV_INFO_SIZE, TLV_PROT_INFO_MAGIC, TlvInfo, TlvKind,
};

/// The small TLV buffer `Image::read_from` is checked with: 4 KiB, the size the
/// `Image::read_from` docs suggest for one ML-DSA-65 signature and the usual MCUboot TLVs.
pub const SMALL_TLV_BUF: usize = 4096;

/// A TLV buffer that fits any image: two areas of at most `4 + u16::MAX` bytes.
pub const FULL_TLV_BUF: usize = 2 * (TLV_INFO_SIZE + u16::MAX as usize);

/// The panic message when the parser and the reference parser disagree.
/// `scripts/fuzz.sh tp1` looks for it in the fuzzer's output.
pub const DISAGREEMENT: &str = "Image::parse disagrees with the reference parser";

/// What [`check_parse_image`] saw, for the tests and the corpus expectations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// `Image::parse` of the input.
    pub parse: Result<(), ParseError>,
    /// `Image::read_from` of the input with a [`SMALL_TLV_BUF`]-byte TLV buffer.
    pub read_from_small: Result<(), Error>,
    /// The kind of every TLV of the parsed image (protected area first), or none.
    pub kinds: Vec<TlvKind>,
}

/// Check the parser on `data`, panicking on any disagreement or broken invariant (the
/// fuzz "crash"). In order:
///
/// 1. `Image::parse` matches [`oracle::parse`]: the same error, or the same hashed end,
///    `tlv_end` and (protected, type, value offset, value length) of every TLV.
/// 2. A parsed image is consistent with the input: header, areas and TLVs in bounds and
///    tiling their areas, the header and area bytes equal to the input's, `tlvs()` the
///    protected TLVs then the unprotected ones, `pairs()` equal to `iter()` and
///    `kind()` equal to `TlvKind::of`.
/// 3. `Image::read_from` with a [`FULL_TLV_BUF`] buffer follows its contract: the image
///    `Image::parse` finds, or `Truncated` when parsing fails, or `Image::parse`'s error;
///    never `TlvAreaTooLarge` (or `Read`, from a byte-slice reader).
/// 4. With a [`SMALL_TLV_BUF`] buffer, the same, except `TlvAreaTooLarge` exactly when
///    the TLV areas fit the input but not the buffer.
pub fn check_parse_image(data: &[u8]) -> Report {
    // 1. The parser against the reference parser.
    let parsed = Image::parse(data);
    let expected = oracle::parse(data);
    let seen = parsed
        .as_ref()
        .map(|image| as_oracle(data, image))
        .map_err(|e| *e);
    assert!(
        seen == expected,
        "{DISAGREEMENT}: parser {seen:?}, reference {expected:?}"
    );

    // 2. Invariants of a parsed image.
    let mut kinds = Vec::new();
    if let Ok(image) = &parsed {
        check_image(data, image, &mut kinds);
    }

    // 3. read_from with a buffer that fits any image.
    let mut full_buf = vec![0u8; FULL_TLV_BUF];
    let full = read_from(data, &mut full_buf);
    match &full {
        Ok(image) => assert!(
            matches!(&parsed, Ok(p) if p == image),
            "Image::read_from (full buffer) found {image:?}, Image::parse {parsed:?}"
        ),
        Err(Error::Parse(ParseError::Truncated)) => assert!(
            parsed.is_err(),
            "Image::read_from (full buffer) is Truncated, Image::parse {parsed:?}"
        ),
        Err(e @ (Error::TlvAreaTooLarge | Error::Read(_))) => {
            panic!("Image::read_from (full buffer) returned {e:?}")
        }
        Err(e) => assert_eq!(
            Err(*e),
            parsed.map(|_| ()).map_err(Error::Parse),
            "Image::read_from (full buffer) and Image::parse report different errors"
        ),
    }

    // 4. read_from with the small buffer.
    let mut small_buf = vec![0u8; SMALL_TLV_BUF];
    let small = read_from(data, &mut small_buf);
    match tlv_areas_to_buffer(data) {
        Some(total) if total > SMALL_TLV_BUF as u64 => assert_eq!(
            small.map(|_| ()),
            Err(Error::TlvAreaTooLarge),
            "Image::read_from (small buffer): {total} bytes of TLV areas"
        ),
        _ => assert!(
            same_result(&small, &full),
            "Image::read_from: small buffer {small:?}, full buffer {full:?}"
        ),
    }

    // Sort the outcomes into the coverage arms.
    let parse = parsed.map(|_| ());
    let read_from_small = small.map(|_| ());
    std::hint::black_box(cov::parse_outcome(parse));
    std::hint::black_box(cov::read_from_outcome(read_from_small));
    Report {
        parse,
        read_from_small,
        kinds,
    }
}

/// `Image::read_from` over the bytes `data` (a byte slice is an `ImageReader`).
fn read_from<'b>(data: &[u8], tlv_buf: &'b mut [u8]) -> Result<Image<'b>, Error> {
    let mut reader = data;
    Image::read_from(&mut reader, tlv_buf)
}

/// Whether two `read_from` results are the same image or the same error.
fn same_result(a: &Result<Image<'_>, Error>, b: &Result<Image<'_>, Error>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

/// The parsed image in the reference parser's terms.
fn as_oracle(data: &[u8], image: &Image<'_>) -> oracle::Parsed {
    let base = data.as_ptr() as usize;
    oracle::Parsed {
        hashed_end: u64::from(image.hashed_range().end),
        tlv_end: u64::from(image.tlv_end()),
        tlvs: image
            .tlvs()
            .map(|t| {
                let offset = (t.value.as_ptr() as usize).wrapping_sub(base);
                (t.protected, t.tlv_type, offset, t.value.len())
            })
            .collect(),
    }
}

/// The size of the TLV areas `read_from` must buffer, `protect_tlv_size + max(tlv_tot,
/// 4)`, when every check before the buffer passes: the header parses, the hashed region
/// fits `u32`, the unprotected info header fits the input and the TLV areas fit the
/// input. Computed from the header and info bytes, not by the parser.
fn tlv_areas_to_buffer(data: &[u8]) -> Option<u64> {
    let len = data.len() as u64;
    let byte = |at: u64| data.get(usize::try_from(at).ok()?).copied();
    let u16_at = |at: u64| Some(u16::from_le_bytes([byte(at)?, byte(at + 1)?]));
    let u32_at = |at: u64| {
        Some(u32::from_le_bytes([
            byte(at)?,
            byte(at + 1)?,
            byte(at + 2)?,
            byte(at + 3)?,
        ]))
    };
    if len < IMAGE_HEADER_SIZE as u64 || u32_at(0)? != IMAGE_MAGIC {
        return None;
    }
    let hdr = u64::from(u16_at(8)?);
    let prot = u64::from(u16_at(10)?);
    let img = u64::from(u32_at(12)?);
    if hdr < IMAGE_HEADER_SIZE as u64 {
        return None;
    }
    let tlv_off = hdr + img;
    let hashed = tlv_off + prot;
    if hashed > u64::from(u32::MAX) || hashed + 4 > len {
        return None;
    }
    let total = prot + u64::from(u16_at(hashed + 2)?.max(4));
    (tlv_off + total <= len).then_some(total)
}

/// Step 2 of [`check_parse_image`]: the invariants of an image parsed from `data`.
fn check_image(data: &[u8], image: &Image<'_>, kinds: &mut Vec<TlvKind>) {
    let base = data.as_ptr() as usize;
    let offset = |s: &[u8]| (s.as_ptr() as usize).wrapping_sub(base);
    let header = image.header();

    // The header: its bytes are the input's first 32, and it parses the same alone.
    assert_eq!(&image.raw_header()[..], &data[..IMAGE_HEADER_SIZE]);
    assert_eq!(Header::parse(data), Ok(*header));
    let raw = RawHeader::parse(data).expect("the header of a parsed image parses");
    assert_eq!(raw.header(), header);
    assert_eq!(raw.bytes(), image.raw_header());

    // The areas: protected (if any) ends where the hashed region does, unprotected
    // starts there and ends at tlv_end, inside the input.
    let hashed = image.hashed_range();
    assert_eq!(hashed.start, 0);
    assert_eq!(header.hashed_len(), Ok(hashed.end));
    assert!(hashed.end <= image.tlv_end());
    assert!(image.tlv_end() as usize <= data.len());
    let unprotected = image.unprotected();
    assert!(!unprotected.is_protected());
    assert_eq!(unprotected.range(), hashed.end..image.tlv_end());
    match image.protected() {
        Some(p) => {
            assert!(p.is_protected());
            assert_ne!(header.protect_tlv_size, 0);
            assert_eq!(Ok(p.range().start), header.tlv_offset());
            assert_eq!(p.range().end, hashed.end);
        }
        None => assert_eq!(header.protect_tlv_size, 0),
    }

    for area in image.protected().into_iter().chain([unprotected]) {
        let (start, end) = (area.range().start as usize, area.range().end as usize);
        assert!(start <= end && end <= data.len());
        // The area's bytes are the input's, its info header included.
        assert_eq!(area.bytes(), &data[start..end]);
        assert_eq!(offset(area.bytes()), start);
        let info = TlvInfo::parse(area.bytes()).expect("an area holds its info header");
        let magic = if area.is_protected() {
            TLV_PROT_INFO_MAGIC
        } else {
            TLV_INFO_MAGIC
        };
        assert_eq!(info.magic, magic);
        assert_eq!(usize::from(info.tlv_tot), end - start);

        // The TLVs tile the area: each header follows the previous value, and the last
        // value ends at the area's end.
        let mut next = start + TLV_INFO_SIZE;
        for tlv in area.iter() {
            let value_at = offset(tlv.value);
            assert_eq!(value_at, next + TLV_HEADER_SIZE, "TLVs tile their area");
            assert!(value_at + tlv.value.len() <= end, "TLV value past its area");
            assert_eq!(data[next..next + 2], tlv.tlv_type.to_le_bytes());
            assert_eq!(
                usize::from(u16::from_le_bytes([data[next + 2], data[next + 3]])),
                tlv.value.len()
            );
            assert_eq!(tlv.protected, area.is_protected());
            assert_eq!(tlv.kind(), TlvKind::of(tlv.tlv_type));
            assert_eq!(tlv.as_pair(), (tlv.tlv_type, tlv.value));
            assert_eq!(<(u16, &[u8])>::from(tlv), tlv.as_pair());
            std::hint::black_box(cov::tlv_kind(tlv.kind()));
            kinds.push(tlv.kind());
            next = value_at + tlv.value.len();
        }
        assert_eq!(next, end, "the TLVs exactly fill their area");
        assert!(area.pairs().eq(area.iter().map(|t| t.as_pair())));
    }

    // tlvs() is the protected area's TLVs, then the unprotected area's.
    let areas = image.protected().into_iter().chain([unprotected]);
    assert!(image.tlvs().eq(areas.flat_map(|a| a.iter())));
}

/// One match arm per outcome, each on its own line with a `// cov:` marker that
/// `scripts/fuzz_coverage_check.py` requires `cargo fuzz coverage` to reach. The
/// functions return the arm's index (the tests check the committed corpus reaches each).
/// The `_` arms (variants added later; the enums are `#[non_exhaustive]`) carry no
/// marker.
pub mod cov {
    use keelsign_verify::Error;
    use keelsign_verify::image::{ParseError as P, TlvKind as K};

    /// Arms of [`parse_outcome`] that are errors: indices `1..=8`, the `ParseError`
    /// variants.
    pub const PARSE_ERROR_ARMS: core::ops::RangeInclusive<usize> = 1..=8;
    /// Arms of [`read_from_outcome`] that are errors: `Error::Parse`, then
    /// `Error::TlvAreaTooLarge`.
    pub const READ_FROM_ERROR_ARMS: core::ops::RangeInclusive<usize> = 1..=2;
    /// Number of [`tlv_kind`] arms, one per `TlvKind` variant.
    pub const TLV_KIND_ARMS: usize = 19;

    /// The arm of an `Image::parse` outcome: 0 for `Ok`, 1–8 for the `ParseError`s.
    pub fn parse_outcome(r: Result<(), P>) -> usize {
        match r {
            Ok(()) => 0,
            Err(P::BadMagic) => 1,              // cov: ParseError::BadMagic
            Err(P::Truncated) => 2,             // cov: ParseError::Truncated
            Err(P::HeaderTooSmall) => 3,        // cov: ParseError::HeaderTooSmall
            Err(P::SizeOverflow) => 4,          // cov: ParseError::SizeOverflow
            Err(P::BadTlvInfoMagic) => 5,       // cov: ParseError::BadTlvInfoMagic
            Err(P::ProtectedSizeMismatch) => 6, // cov: ParseError::ProtectedSizeMismatch
            Err(P::LengthMismatch) => 7,        // cov: ParseError::LengthMismatch
            Err(P::PqSignatureTooLong) => 8,    // cov: ParseError::PqSignatureTooLong
            Err(_) => usize::MAX,
        }
    }

    /// The arm of an `Image::read_from` outcome (small buffer): 0 for `Ok`, 1 for
    /// `Error::Parse`, 2 for `Error::TlvAreaTooLarge`.
    pub fn read_from_outcome(r: Result<(), Error>) -> usize {
        match r {
            Ok(()) => 0,
            Err(Error::Parse(_)) => 1,        // cov: Error::Parse
            Err(Error::TlvAreaTooLarge) => 2, // cov: Error::TlvAreaTooLarge
            Err(_) => usize::MAX,
        }
    }

    /// The arm of a TLV kind: 0–18, one per `TlvKind` variant.
    pub fn tlv_kind(k: K) -> usize {
        match k {
            K::KeyHash => 0,              // cov: TlvKind::KeyHash
            K::PubKey => 1,               // cov: TlvKind::PubKey
            K::Sha256 => 2,               // cov: TlvKind::Sha256
            K::Sha384 => 3,               // cov: TlvKind::Sha384
            K::Sha512 => 4,               // cov: TlvKind::Sha512
            K::Rsa2048Pss => 5,           // cov: TlvKind::Rsa2048Pss
            K::EcdsaSig => 6,             // cov: TlvKind::EcdsaSig
            K::Rsa3072Pss => 7,           // cov: TlvKind::Rsa3072Pss
            K::Ed25519 => 8,              // cov: TlvKind::Ed25519
            K::SigPure => 9,              // cov: TlvKind::SigPure
            K::Dependency => 10,          // cov: TlvKind::Dependency
            K::SecCnt => 11,              // cov: TlvKind::SecCnt
            K::BootRecord => 12,          // cov: TlvKind::BootRecord
            K::KeelsignKeyId => 13,       // cov: TlvKind::KeelsignKeyId
            K::MlDsa44Sig => 14,          // cov: TlvKind::MlDsa44Sig
            K::MlDsa65Sig => 15,          // cov: TlvKind::MlDsa65Sig
            K::LmsHssSig => 16,           // cov: TlvKind::LmsHssSig
            K::KeelsignReserved(_) => 17, // cov: TlvKind::KeelsignReserved
            K::Unknown(_) => 18,          // cov: TlvKind::Unknown
            _ => usize::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// One `fuzz/corpus/MANIFEST.json` seed entry.
    struct Seed {
        name: String,
        bytes: usize,
        expect_parse: String,
        expect_read_from_4k: String,
    }

    fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
    }

    /// The seeds of `fuzz/corpus/MANIFEST.json`. It is `json.dumps(indent=2)` output
    /// from scripts/gen_fuzz_corpus.py: each seed is a `"name.bin": {` line at four
    /// spaces, then one scalar field per line at six spaces.
    fn seeds() -> Vec<Seed> {
        let text = std::fs::read_to_string(corpus_dir().join("MANIFEST.json")).unwrap();
        let mut seeds = Vec::new();
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut name: Option<String> = None;
        for line in text.lines() {
            if let Some(n) = line
                .strip_prefix("    \"")
                .and_then(|l| l.strip_suffix("\": {"))
            {
                name = Some(n.to_owned());
                fields.clear();
            } else if let Some(field) = line.strip_prefix("      \"") {
                let (key, value) = field.split_once("\": ").unwrap();
                let value = value.trim_end_matches(',').trim_matches('"');
                fields.push((key.to_owned(), value.to_owned()));
            } else if line.starts_with("    }")
                && let Some(n) = name.take()
            {
                let get = |k: &str| {
                    let found = fields.iter().find(|(key, _)| key == k);
                    found.unwrap_or_else(|| panic!("{n}: no {k}")).1.clone()
                };
                seeds.push(Seed {
                    bytes: get("bytes").parse().unwrap(),
                    expect_parse: get("expect_parse"),
                    expect_read_from_4k: get("expect_read_from_4k"),
                    name: n,
                });
            }
        }
        assert!(seeds.len() > 50, "{} seeds", seeds.len());
        seeds
    }

    fn seed_bytes(seed: &Seed) -> Vec<u8> {
        std::fs::read(corpus_dir().join("parse_image").join(&seed.name)).unwrap()
    }

    /// SHA-39 AC1 (supporting): every committed seed passes `check_parse_image`, the
    /// fuzz target's whole body, without panicking.
    #[test]
    fn every_seed_passes_the_check() {
        let mut ok = 0;
        for seed in seeds() {
            let report = check_parse_image(&seed_bytes(&seed));
            ok += usize::from(report.parse.is_ok());
        }
        assert!(ok > 40, "{ok} seeds parse");
    }

    /// SHA-39 AC2 (supporting): every seed is the size its manifest entry records, and
    /// `Image::parse` and `Image::read_from` (4 KiB buffer) give the recorded results.
    #[test]
    fn every_seed_matches_its_manifest_expectations() {
        for seed in seeds() {
            let data = seed_bytes(&seed);
            assert_eq!(data.len(), seed.bytes, "{}", seed.name);
            let report = check_parse_image(&data);
            let parse = match report.parse {
                Ok(()) => "Ok".to_owned(),
                Err(e) => format!("{e:?}"),
            };
            assert_eq!(parse, seed.expect_parse, "{}", seed.name);
            let read = match report.read_from_small {
                Ok(()) => "Ok".to_owned(),
                Err(e) => format!("{e:?}"),
            };
            assert_eq!(read, seed.expect_read_from_4k, "{}", seed.name);
        }
    }

    /// SHA-39 TP2 (deterministic counterpart of `scripts/fuzz.sh coverage`): the
    /// committed corpus reaches every `cov` arm: all 19 TLV kinds, all 8 `ParseError`
    /// variants, and `Error::Parse` and `Error::TlvAreaTooLarge` from `read_from`.
    #[test]
    fn committed_corpus_reaches_every_tlv_kind_and_error_variant() {
        let (mut kinds, mut parse, mut read) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for seed in seeds() {
            let report = check_parse_image(&seed_bytes(&seed));
            kinds.extend(report.kinds.into_iter().map(cov::tlv_kind));
            parse.insert(cov::parse_outcome(report.parse));
            read.insert(cov::read_from_outcome(report.read_from_small));
        }
        assert_eq!(kinds, (0..cov::TLV_KIND_ARMS).collect(), "TLV kinds");
        for arm in cov::PARSE_ERROR_ARMS {
            assert!(parse.contains(&arm), "parse arm {arm}: {parse:?}");
        }
        for arm in cov::READ_FROM_ERROR_ARMS {
            assert!(read.contains(&arm), "read_from arm {arm}: {read:?}");
        }
        assert!(!parse.contains(&usize::MAX) && !read.contains(&usize::MAX));
    }
}
