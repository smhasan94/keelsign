//! The single verify entry point (SHA-46): [`verify`] / [`verify_with`] read an image from
//! a slot, enforce the image rules, compute the image digest `M` and verify the halves
//! the device's [`Policy`] requires, returning a [`VerifiedImage`] for the caller's
//! anti-rollback check.
//!
//! The policies, the image rules (with their MCUboot citations), the error precedence
//! and the full policy × image matrix are specified in
//! [docs/policy.md](https://github.com/smhasan94/keelsign/blob/main/docs/policy.md).
//!
//! # Error precedence
//!
//! When an image has several faults, the first check in this order decides the error:
//!
//! 0. [`Error::Ed25519`]`(`[`Ed25519Error::NotEnabled`]`)` if the policy requires the
//!    Ed25519 half and the `ed25519` feature is off, before anything is read.
//! 1. [`Image::read_from`]: [`Error::Parse`], [`Error::Read`], [`Error::TlvAreaTooLarge`].
//! 2. Header flags: [`ImageError::Encrypted`], then [`ImageError::Compressed`], then
//!    [`ImageError::NonBootable`].
//! 3. The first TLV of the keelsign block (`0x4BA0..=0x4BAF`) in the protected area:
//!    [`ImageError::KeelsignTlvProtected`].
//! 4. A `SIG_PURE` TLV (`0x25`) in either area: [`ImageError::SigPure`].
//! 5. `SHA256` TLVs (`0x10`) counted over both areas: none is
//!    [`ImageError::MissingSha256Tlv`], more than one [`ImageError::MultipleSha256Tlvs`],
//!    a length other than 32 [`ImageError::InvalidSha256Tlv`].
//! 6. Protected `SEC_CNT` TLVs (`0x50`): more than one is
//!    [`ImageError::MultipleSecurityCounters`], a length other than 4
//!    [`ImageError::InvalidSecurityCounter`]. An unprotected `SEC_CNT` is ignored.
//! 7. [`image_digest`] ([`Error::Read`], [`Error::ChunkBufferEmpty`]), then a digest
//!    other than the `SHA256` TLV: [`ImageError::DigestMismatch`].
//! 8. The classical half, if [`Policy::requires_ed25519`], over the unprotected area:
//!    [`select_ed25519_signature`]'s errors ([`Ed25519Error::Missing`],
//!    [`Ed25519Error::Multiple`], [`Ed25519Error::Unpaired`],
//!    [`Ed25519Error::InvalidKeyHash`], [`Ed25519Error::InvalidSignatureLength`]), then
//!    [`Ed25519Error::KeyNotTrusted`], [`Ed25519Error::InvalidPublicKey`] and
//!    [`Ed25519Error::SignatureInvalid`], each wrapped in [`Error::Ed25519`].
//! 9. The post-quantum half, if [`Policy::requires_pq`]: [`verify_pq_with`] over the
//!    unprotected area, with its own order (the flat [`Error`] variants).
//! 10. `Ok(`[`VerifiedImage`]`)`.

use core::fmt;

use crate::backend::DefaultBackend;
use crate::digest::image_digest;
use crate::dispatch::{Backend, verify_pq_with};
use crate::ed25519::{self, Ed25519Error, Ed25519Key, select_ed25519_signature};
use crate::error::Error;
use crate::image::{IMAGE_TLV_SEC_CNT, IMAGE_TLV_SHA256, IMAGE_TLV_SIG_PURE, Image, ImageVersion};
use crate::reader::ImageReader;
use crate::tlv::KEELSIGN_TLV_RANGE;
use crate::trusted_keys::{TrustedKey, TrustedKeys};

/// Which signatures a device requires on an image.
///
/// There is no default: a device must choose, and an unset policy cannot silently mean
/// "accept". Whatever the policy, the image rules ([`ImageError`]) apply.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    /// The Ed25519 half only (MCUboot's KEYHASH + ED25519 pair); keelsign TLVs are
    /// ignored. A transition mode for fleets that do not verify post-quantum signatures
    /// yet. Needs the `ed25519` feature.
    ClassicalOnly,
    /// The post-quantum half only (keelsign key ID + one PQ signature TLV); a KEYHASH +
    /// ED25519 pair, if present, is ignored.
    PqOnly,
    /// Both halves, each over the same digest `M`. Needs the `ed25519` feature.
    Hybrid,
}

impl Policy {
    /// Every policy.
    pub const ALL: &'static [Policy] = &[Policy::ClassicalOnly, Policy::PqOnly, Policy::Hybrid];

    /// Whether the policy verifies the Ed25519 half: [`Policy::ClassicalOnly`] and
    /// [`Policy::Hybrid`].
    pub const fn requires_ed25519(self) -> bool {
        matches!(self, Policy::ClassicalOnly | Policy::Hybrid)
    }

    /// Whether the policy verifies the post-quantum half: [`Policy::PqOnly`] and
    /// [`Policy::Hybrid`].
    pub const fn requires_pq(self) -> bool {
        matches!(self, Policy::PqOnly | Policy::Hybrid)
    }
}

/// An image-level rule the image breaks, whatever the policy. Wrapped in
/// [`Error::Image`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// `IMAGE_F_ENCRYPTED_AES128` or `IMAGE_F_ENCRYPTED_AES256` is set: encrypted images
    /// are not supported (the digest would have to be over the plaintext).
    Encrypted,
    /// An `IMAGE_F_COMPRESSED_*` flag is set: compressed images are not supported.
    Compressed,
    /// `IMAGE_F_NON_BOOTABLE` is set: the image must not be booted.
    NonBootable,
    /// A TLV of the keelsign block (`0x4BA0..=0x4BAF`, the type given) is in the
    /// protected area. keelsign TLVs are unprotected-only; reserved IDs are never emitted.
    KeelsignTlvProtected(u16),
    /// A `SIG_PURE` TLV (`0x25`): the signature would be over the image itself, not `M`.
    SigPure,
    /// No `SHA256` TLV in either area (an image hashed only with SHA-384 or SHA-512 too).
    MissingSha256Tlv,
    /// More than one `SHA256` TLV, counting both areas.
    MultipleSha256Tlvs,
    /// The `SHA256` TLV is not 32 bytes.
    InvalidSha256Tlv,
    /// More than one protected `SEC_CNT` TLV.
    MultipleSecurityCounters,
    /// The protected `SEC_CNT` TLV is not 4 bytes.
    InvalidSecurityCounter,
    /// The image digest `M` is not the `SHA256` TLV value: the image changed after it was
    /// hashed.
    DigestMismatch,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageError::Encrypted => f.write_str("encrypted images are not supported"),
            ImageError::Compressed => f.write_str("compressed images are not supported"),
            ImageError::NonBootable => f.write_str("image is flagged non-bootable"),
            ImageError::KeelsignTlvProtected(t) => {
                write!(f, "keelsign TLV {t:#06x} is in the protected area")
            }
            ImageError::SigPure => f.write_str("SIG_PURE images are not supported"),
            ImageError::MissingSha256Tlv => f.write_str("no SHA256 TLV"),
            ImageError::MultipleSha256Tlvs => f.write_str("more than one SHA256 TLV"),
            ImageError::InvalidSha256Tlv => f.write_str("SHA256 TLV has the wrong length"),
            ImageError::MultipleSecurityCounters => {
                f.write_str("more than one protected SEC_CNT TLV")
            }
            ImageError::InvalidSecurityCounter => f.write_str("SEC_CNT TLV has the wrong length"),
            ImageError::DigestMismatch => f.write_str("image digest does not match the SHA256 TLV"),
        }
    }
}

impl core::error::Error for ImageError {}

/// An image that passed [`verify`] / [`verify_with`] under [`VerifiedImage::policy`].
///
/// Only those two functions produce one. Everything it reports was covered by the
/// verified signatures: the version comes from the header and the security counter from
/// the protected TLV area, both hashed from the copy that was parsed. Anti-rollback is the
/// caller's decision: compare [`VerifiedImage::version`] with
/// [`ImageVersion::cmp_ignoring_build_num`] (MCUboot's default) or
/// [`ImageVersion::cmp_with_build_num`], and/or [`VerifiedImage::security_counter`] with
/// the device's stored counter.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedImage<'k> {
    /// The policy the image was verified under.
    pub policy: Policy,
    /// The header's `ih_ver`.
    pub version: ImageVersion,
    /// The protected `SEC_CNT` TLV value, if there is one (an unprotected one is ignored,
    /// as MCUboot reads it with `prot = true`).
    pub security_counter: Option<u32>,
    /// The image digest `M` both signatures are over (also the `SHA256` TLV value).
    pub digest: [u8; 32],
    /// Where the image ends ([`Image::tlv_end`]): header, body and both TLV areas.
    pub image_len: u32,
    /// The trusted post-quantum key that verified the image, when the policy requires
    /// the post-quantum half.
    pub pq_key: Option<TrustedKey<'k>>,
    /// The trusted Ed25519 key that verified the image, when the policy requires the
    /// Ed25519 half.
    pub ed25519_key: Option<Ed25519Key<'k>>,
}

/// What the image rules extract from a parsed image.
struct ImageFacts<'t> {
    sha256: &'t [u8],
    security_counter: Option<u32>,
}

/// The image rules that need no digest (steps 2 to 6 of the precedence).
fn check_image<'t>(image: &Image<'t>) -> Result<ImageFacts<'t>, ImageError> {
    let flags = image.header().flags;
    if flags.is_encrypted() {
        return Err(ImageError::Encrypted);
    }
    if flags.is_compressed() {
        return Err(ImageError::Compressed);
    }
    if flags.non_bootable() {
        return Err(ImageError::NonBootable);
    }
    let protected = image
        .protected()
        .map(|area| area.iter())
        .into_iter()
        .flatten();
    if let Some(tlv) = protected
        .clone()
        .find(|tlv| KEELSIGN_TLV_RANGE.contains(&tlv.tlv_type))
    {
        return Err(ImageError::KeelsignTlvProtected(tlv.tlv_type));
    }
    if image.tlvs().any(|tlv| tlv.tlv_type == IMAGE_TLV_SIG_PURE) {
        return Err(ImageError::SigPure);
    }
    let mut hashes = image.tlvs().filter(|tlv| tlv.tlv_type == IMAGE_TLV_SHA256);
    let sha256 = hashes.next().ok_or(ImageError::MissingSha256Tlv)?.value;
    if hashes.next().is_some() {
        return Err(ImageError::MultipleSha256Tlvs);
    }
    if sha256.len() != 32 {
        return Err(ImageError::InvalidSha256Tlv);
    }
    let mut counters = protected.filter(|tlv| tlv.tlv_type == IMAGE_TLV_SEC_CNT);
    let security_counter = match counters.next() {
        None => None,
        Some(tlv) => {
            if counters.next().is_some() {
                return Err(ImageError::MultipleSecurityCounters);
            }
            let bytes: [u8; 4] = tlv
                .value
                .try_into()
                .map_err(|_| ImageError::InvalidSecurityCounter)?;
            Some(u32::from_le_bytes(bytes))
        }
    };
    Ok(ImageFacts {
        sha256,
        security_counter,
    })
}

/// Verify the image in `reader` under `policy` against `keys`, with the built-in
/// [`DefaultBackend::new`] (LMS/HSS under the keelsign default parameter policy).
///
/// This is [`verify_with`]`(&DefaultBackend::new(), reader, keys, policy, tlv_buf,
/// chunk)`; see there and the [module docs](self#error-precedence) for the order of the
/// checks.
pub fn verify<'k, R, const N: usize, const E: usize>(
    reader: &mut R,
    keys: &TrustedKeys<'k, N, E>,
    policy: Policy,
    tlv_buf: &mut [u8],
    chunk: &mut [u8],
) -> Result<VerifiedImage<'k>, Error>
where
    R: ImageReader + ?Sized,
{
    verify_with(&DefaultBackend::new(), reader, keys, policy, tlv_buf, chunk)
}

/// Verify the image in `reader` under `policy` against `keys`, with `backend` for the
/// post-quantum half (for example [`DefaultBackend::cnsa_2_0`]).
///
/// No heap: the TLV areas are read into `tlv_buf` (4 KiB fits an ML-DSA-65 or a
/// two-level HSS signature plus the MCUboot TLVs, see [`Image::read_from`]) and the body
/// is hashed through `chunk` ([`DEFAULT_CHUNK_LEN`](crate::DEFAULT_CHUNK_LEN) bytes is
/// MCUboot's buffer). The checks run in the order of the
/// [module docs](self#error-precedence); the first failure is returned.
///
/// # Example
///
/// ```
/// use keelsign_verify::{
///     DEFAULT_CHUNK_LEN, Error, ImageError, Policy, TrustedKeys, verify,
/// };
///
/// # const IMAGE: [u8; 48] = [
/// #     0x3D, 0xB8, 0xF3, 0x96, 0, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
/// #     1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD,
/// #     0x07, 0x69, 12, 0, 0x50, 0, 4, 0, 7, 0, 0, 0,
/// # ];
/// let mut slot: &[u8] = &IMAGE; // or a NorFlashReader over the DFU slot
/// let keys = TrustedKeys::<1>::new(&[])?;
/// let mut tlv_buf = [0u8; 4096];
/// let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
/// // This image has no SHA256 TLV, so it fails under every policy.
/// assert_eq!(
///     verify(&mut slot, &keys, Policy::PqOnly, &mut tlv_buf, &mut chunk),
///     Err(Error::Image(ImageError::MissingSha256Tlv))
/// );
/// # Ok::<(), keelsign_verify::KeySetError>(())
/// ```
pub fn verify_with<'k, B, R, const N: usize, const E: usize>(
    backend: &B,
    reader: &mut R,
    keys: &TrustedKeys<'k, N, E>,
    policy: Policy,
    tlv_buf: &mut [u8],
    chunk: &mut [u8],
) -> Result<VerifiedImage<'k>, Error>
where
    B: Backend + ?Sized,
    R: ImageReader + ?Sized,
{
    // 0. Fail closed before touching the slot if the build cannot verify the half the
    // policy needs.
    if policy.requires_ed25519() && !ed25519::is_enabled() {
        return Err(Error::Ed25519(Ed25519Error::NotEnabled));
    }
    // 1. Header and TLV areas.
    let image = Image::read_from(reader, tlv_buf)?;
    // 2-6. Image rules.
    let facts = check_image(&image)?;
    // 7. The digest, over the parsed header and protected area and the streamed body.
    let digest = image_digest(reader, &image, chunk)?;
    if digest.as_slice() != facts.sha256 {
        return Err(ImageError::DigestMismatch.into());
    }
    // 8. The classical half.
    let ed25519_key = if policy.requires_ed25519() {
        let selected = select_ed25519_signature(image.unprotected().pairs())?;
        let key = *keys.find_ed25519(selected.keyhash)?;
        ed25519::verify_signature(key.public_key, &digest, selected.signature)?;
        Some(key)
    } else {
        None
    };
    // 9. The post-quantum half.
    let pq_key = if policy.requires_pq() {
        Some(verify_pq_with(
            backend,
            keys,
            image.unprotected().pairs(),
            &digest,
        )?)
    } else {
        None
    };
    Ok(VerifiedImage {
        policy,
        version: image.header().version,
        security_counter: facts.security_counter,
        digest,
        image_len: image.tlv_end(),
        pq_key,
        ed25519_key,
    })
}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use core::cell::Cell;
    use std::format;
    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::algorithm::Algorithm;
    use crate::image::test_support::{area_bytes, set_u32, synth};
    use crate::image::{
        IMAGE_F_COMPRESSED_ARM_THUMB_FLT, IMAGE_F_COMPRESSED_LZMA1, IMAGE_F_COMPRESSED_LZMA2,
        IMAGE_F_ENCRYPTED_AES128, IMAGE_F_ENCRYPTED_AES256, IMAGE_F_NON_BOOTABLE,
        IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH, IMAGE_TLV_SHA384, TLV_INFO_MAGIC,
    };
    use crate::image::{IMAGE_TLV_SHA512, ParseError};
    use crate::reader::mock::Recording;
    use crate::tlv::{TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG};
    use crate::trusted_keys::key_id_of;

    const MANIFEST: &str = include_str!("../../tests/fixtures/images/MANIFEST.json");
    const SPKI: &[u8] =
        include_bytes!("../../tests/fixtures/images/keys/ed25519-test-key.spki.der");
    const HYBRID: &[u8] =
        include_bytes!("../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin");

    macro_rules! fixture {
        ($name:literal) => {
            (
                $name,
                include_bytes!(concat!("../../tests/fixtures/images/", $name)).as_slice(),
            )
        };
    }

    /// Every little-endian fixture image that existed before SHA-46 (the manifest-driven
    /// matrix over every image is `tests/policy_matrix.rs`).
    const FIXTURES: [(&str, &[u8]); 12] = [
        fixture!("mcuboot-rsa2048.bin"),
        fixture!("mcuboot-ecdsa-p256.bin"),
        fixture!("mcuboot-ed25519.bin"),
        fixture!("mcuboot-ed25519-padded.bin"),
        fixture!("mcuboot-ed25519-200k.bin"),
        fixture!("keelsign-lms-m32-h5.bin"),
        fixture!("keelsign-hss2-m32-h5h5.bin"),
        fixture!("keelsign-lms-protected-tlvs.bin"),
        fixture!("keelsign-hybrid-ed25519-lms.bin"),
        fixture!("keelsign-mldsa44.bin"),
        fixture!("keelsign-mldsa65.bin"),
        fixture!("keelsign-dual-pq-invalid.bin"),
    ];

    static ED_KEY: [u8; 32] = ed_key();
    static LMS_PK: [u8; 60] = crate::lms::test_public_key(0xA0);

    const fn ed_key() -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = SPKI[12 + i];
            i += 1;
        }
        out
    }

    /// The `public_key_hex` and `algorithm` of a fixture's MANIFEST.json entry, if any.
    fn manifest_key(name: &str) -> Option<(Algorithm, Vec<u8>)> {
        let start = MANIFEST.find(&format!("\"{name}\": {{"))?;
        let entry = &MANIFEST[start..];
        let entry = &entry[..entry.find("\n    }").unwrap()];
        let field = |key: &str| {
            let needle = format!("\"{key}\": \"");
            let at = entry.find(&needle)? + needle.len();
            Some(&entry[at..at + entry[at..].find('"').unwrap()])
        };
        let hex = field("public_key_hex")?;
        let algorithm = match field("algorithm")? {
            "LmsHss" => Algorithm::LmsHss,
            "MlDsa44" => Algorithm::MlDsa44,
            "MlDsa65" => Algorithm::MlDsa65,
            other => panic!("{other}"),
        };
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        Some((algorithm, bytes))
    }

    /// A backend that counts its calls and returns a fixed result.
    struct CountingBackend {
        result: Result<(), Error>,
        calls: Cell<usize>,
    }

    impl CountingBackend {
        fn returning(result: Result<(), Error>) -> Self {
            Self {
                result,
                calls: Cell::new(0),
            }
        }
    }

    impl Backend for CountingBackend {
        fn verify(&self, _: Algorithm, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            self.result
        }
    }

    /// `verify_with` over `data` with a 4 KiB TLV buffer and a 256-byte chunk.
    fn run<'k, B: Backend, const N: usize, const E: usize>(
        backend: &B,
        data: &[u8],
        keys: &TrustedKeys<'k, N, E>,
        policy: Policy,
    ) -> Result<VerifiedImage<'k>, Error> {
        let mut reader = data;
        let mut tlv_buf = [0u8; 8192];
        let mut chunk = [0u8; 256];
        verify_with(backend, &mut reader, keys, policy, &mut tlv_buf, &mut chunk)
    }

    /// The trusted keys of the synthetic images: the LMS test key and the Ed25519 test
    /// key.
    fn synth_keys() -> TrustedKeys<'static, 2, 1> {
        TrustedKeys::with_ed25519(
            &[TrustedKey {
                algorithm: Algorithm::LmsHss,
                public_key: &LMS_PK,
            }],
            &[Ed25519Key {
                public_key: &ED_KEY,
            }],
        )
        .unwrap()
    }

    /// Write `M` into every 32-byte `SHA256` TLV of the unprotected area.
    fn finish(mut d: Vec<u8>) -> Vec<u8> {
        let image = Image::parse(&d).unwrap();
        let end = image.hashed_range().end as usize;
        let m: [u8; 32] = Sha256::digest(&d[..end]).into();
        let base = d.as_ptr() as usize;
        let at: Vec<usize> = image
            .unprotected()
            .iter()
            .filter(|t| t.tlv_type == IMAGE_TLV_SHA256 && t.value.len() == 32)
            .map(|t| t.value.as_ptr() as usize - base)
            .collect();
        for offset in at {
            d[offset..offset + 32].copy_from_slice(&m);
        }
        d
    }

    /// The keelsign PQ TLVs of a synthetic image (key ID of the LMS test key, junk LMS
    /// signature: only a counting backend "verifies" it).
    fn pq_tlvs() -> [(u16, Vec<u8>); 2] {
        [
            (TLV_KEELSIGN_KEY_ID, key_id_of(&LMS_PK).to_vec()),
            (TLV_LMS_HSS_SIG, [0x5A; 64].to_vec()),
        ]
    }

    /// A synthetic image with a correct SHA256 TLV, the given protected TLVs and extra
    /// unprotected TLVs after the SHA256 one, then the PQ TLVs.
    fn image(protected: Option<&[(u16, Vec<u8>)]>, extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut unprotected: Vec<(u16, Vec<u8>)> =
            Vec::from([(IMAGE_TLV_SHA256, [0; 32].to_vec())]);
        unprotected.extend_from_slice(extra);
        unprotected.extend(pq_tlvs());
        build(protected, &unprotected)
    }

    fn build(protected: Option<&[(u16, Vec<u8>)]>, unprotected: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let prot: Option<Vec<(u16, &[u8])>> =
            protected.map(|p| p.iter().map(|(t, v)| (*t, v.as_slice())).collect());
        let unprot: Vec<(u16, &[u8])> = unprotected
            .iter()
            .map(|(t, v)| (*t, v.as_slice()))
            .collect();
        finish(synth(prot.as_deref(), &unprot))
    }

    /// `data` with its unprotected TLV area rewritten by `edit` (M is unchanged: the
    /// unprotected area is outside it).
    fn edit_unprotected(data: &[u8], edit: impl FnOnce(&mut Vec<(u16, Vec<u8>)>)) -> Vec<u8> {
        let image = Image::parse(data).unwrap();
        let mut tlvs: Vec<(u16, Vec<u8>)> = image
            .unprotected()
            .pairs()
            .map(|(t, v)| (t, v.to_vec()))
            .collect();
        edit(&mut tlvs);
        let pairs: Vec<(u16, &[u8])> = tlvs.iter().map(|(t, v)| (*t, v.as_slice())).collect();
        let mut out = data[..image.hashed_range().end as usize].to_vec();
        out.extend(area_bytes(TLV_INFO_MAGIC, &pairs));
        out
    }

    /// The trusted keys of a fixture: its own PQ key (if the manifest has one) and the
    /// Ed25519 test key.
    fn fixture_keys(name: &str, pk: &'static mut Option<Vec<u8>>) -> TrustedKeys<'static, 2, 1> {
        let ed = [Ed25519Key {
            public_key: &ED_KEY,
        }];
        match manifest_key(name) {
            Some((algorithm, bytes)) => {
                let bytes: &'static [u8] = pk.insert(bytes);
                TrustedKeys::with_ed25519(
                    &[TrustedKey {
                        algorithm,
                        public_key: bytes,
                    }],
                    &ed,
                )
                .unwrap()
            }
            None => TrustedKeys::with_ed25519(&[], &ed).unwrap(),
        }
    }

    /// [`fixture_keys`] with the key bytes leaked (host tests only).
    fn leak_keys(name: &str) -> TrustedKeys<'static, 2, 1> {
        fixture_keys(name, std::boxed::Box::leak(std::boxed::Box::new(None)))
    }

    #[test]
    fn policy_has_no_default_and_requirements_table() {
        assert_eq!(
            Policy::ALL,
            [Policy::ClassicalOnly, Policy::PqOnly, Policy::Hybrid]
        );
        let table: Vec<(Policy, bool, bool)> = Policy::ALL
            .iter()
            .map(|&p| (p, p.requires_ed25519(), p.requires_pq()))
            .collect();
        assert_eq!(
            table,
            [
                (Policy::ClassicalOnly, true, false),
                (Policy::PqOnly, false, true),
                (Policy::Hybrid, true, true),
            ]
        );
        // Every policy requires at least one half: none accepts an unsigned image.
        assert!(
            Policy::ALL
                .iter()
                .all(|p| p.requires_ed25519() || p.requires_pq())
        );
        // `Policy` has no `Default` impl (a device must choose; `verify` takes it by
        // value): the source of this module declares none.
        let source = include_str!("policy.rs");
        assert!(!source.contains(&["impl Default", " for Policy"].concat()));
        assert!(!source.contains(&["#[derive(", "Default"].concat()));
    }

    #[test]
    fn not_enabled_is_refused_before_any_read() {
        let keys = leak_keys("keelsign-hybrid-ed25519-lms.bin");
        for &policy in Policy::ALL {
            let mut reader = Recording::new(HYBRID);
            let mut tlv_buf = [0u8; 4096];
            let mut chunk = [0u8; 256];
            let result = verify(&mut reader, &keys, policy, &mut tlv_buf, &mut chunk);
            if policy.requires_ed25519() && !ed25519::is_enabled() {
                assert_eq!(
                    result,
                    Err(Error::Ed25519(Ed25519Error::NotEnabled)),
                    "{policy:?}"
                );
                assert!(reader.reads.is_empty(), "{policy:?}: no read at all");
            } else {
                // PqOnly is unaffected by the feature; with it on, all three pass.
                let verified = result.unwrap();
                assert_eq!(verified.policy, policy);
                assert!(!reader.reads.is_empty());
            }
        }
        // Even an image that does not parse is NotEnabled first.
        if !ed25519::is_enabled() {
            let mut reader = Recording::new(&[0u8; 8][..]);
            assert_eq!(
                verify(
                    &mut reader,
                    &keys,
                    Policy::Hybrid,
                    &mut [0; 64],
                    &mut [0; 8]
                ),
                Err(Error::Ed25519(Ed25519Error::NotEnabled))
            );
            assert!(reader.reads.is_empty());
        }
    }

    #[test]
    fn every_rejected_flag_bit_is_its_variant() {
        let keys = synth_keys();
        let backend = CountingBackend::returning(Ok(()));
        let base = image(None, &[]);
        assert!(run(&backend, &base, &keys, Policy::PqOnly).is_ok());
        for bit in 0..32 {
            let flag = 1u32 << bit;
            let mut d = base.clone();
            set_u32(&mut d, 16, flag);
            let d = finish(d);
            let expected = match flag {
                IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_ENCRYPTED_AES256 => {
                    Err(Error::Image(ImageError::Encrypted))
                }
                IMAGE_F_COMPRESSED_LZMA1
                | IMAGE_F_COMPRESSED_LZMA2
                | IMAGE_F_COMPRESSED_ARM_THUMB_FLT => Err(Error::Image(ImageError::Compressed)),
                IMAGE_F_NON_BOOTABLE => Err(Error::Image(ImageError::NonBootable)),
                // PIC, RAM_LOAD, ROM_FIXED and unknown bits are accepted, as by MCUboot.
                _ => Ok(()),
            };
            assert_eq!(
                run(&backend, &d, &keys, Policy::PqOnly).map(|_| ()),
                expected,
                "flag {flag:#x}"
            );
        }
        // Combinations: encrypted, then compressed, then non-bootable.
        for (flags, expected) in [
            (
                IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_COMPRESSED_LZMA2 | IMAGE_F_NON_BOOTABLE,
                ImageError::Encrypted,
            ),
            (
                IMAGE_F_COMPRESSED_LZMA1 | IMAGE_F_NON_BOOTABLE,
                ImageError::Compressed,
            ),
            (u32::MAX, ImageError::Encrypted),
            (
                u32::MAX & !(IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_ENCRYPTED_AES256),
                ImageError::Compressed,
            ),
        ] {
            let mut d = base.clone();
            set_u32(&mut d, 16, flags);
            let d = finish(d);
            assert_eq!(
                run(&backend, &d, &keys, Policy::PqOnly).map(|_| ()),
                Err(Error::Image(expected)),
                "flags {flags:#x}"
            );
        }
    }

    #[test]
    fn keelsign_tlv_in_protected_area_is_rejected_for_every_id() {
        let keys = synth_keys();
        let backend = CountingBackend::returning(Ok(()));
        let sec_cnt = (IMAGE_TLV_SEC_CNT, 7u32.to_le_bytes().to_vec());
        for t in KEELSIGN_TLV_RANGE {
            for value_len in [0usize, 16, 64] {
                let d = image(
                    Some(&[sec_cnt.clone(), (t, [0x4B; 64][..value_len].to_vec())]),
                    &[],
                );
                for &policy in Policy::ALL {
                    let result = run(&backend, &d, &keys, policy).map(|_| ());
                    if policy.requires_ed25519() && !ed25519::is_enabled() {
                        assert_eq!(result, Err(Error::Ed25519(Ed25519Error::NotEnabled)));
                    } else {
                        assert_eq!(
                            result,
                            Err(Error::Image(ImageError::KeelsignTlvProtected(t))),
                            "{t:#06x} {policy:?}"
                        );
                    }
                }
            }
        }
        assert_eq!(backend.calls.get(), 0);
        // The first one is named.
        let d = image(
            Some(&[
                (0x4BA7, Vec::new()),
                (TLV_KEELSIGN_KEY_ID, [0; 16].to_vec()),
            ]),
            &[],
        );
        assert_eq!(
            run(&backend, &d, &keys, Policy::PqOnly).map(|_| ()),
            Err(Error::Image(ImageError::KeelsignTlvProtected(0x4BA7)))
        );
        // Just outside the block, and the vendor TLV 0x10A0, are ignored.
        for t in [0x4B9F, 0x4BB0, 0x10A0, 0x00A0] {
            let d = image(Some(&[(t, [1; 8].to_vec())]), &[]);
            assert!(run(&backend, &d, &keys, Policy::PqOnly).is_ok(), "{t:#06x}");
        }
        // A keelsign TLV in the unprotected area is not an image-rule error (a reserved
        // ID there is ignored, docs/image-format.md).
        let d = image(None, &[(0x4BAF, [1; 8].to_vec())]);
        assert!(run(&backend, &d, &keys, Policy::PqOnly).is_ok());
    }

    #[test]
    fn sha256_tlv_rules() {
        let keys = synth_keys();
        let backend = CountingBackend::returning(Ok(()));
        let pq = pq_tlvs();
        let check = |d: &[u8], expected: Result<(), ImageError>| {
            assert_eq!(
                run(&backend, d, &keys, Policy::PqOnly).map(|_| ()),
                expected.map_err(Error::Image)
            );
        };
        // One correct SHA256 TLV.
        check(&image(None, &[]), Ok(()));
        // None, or only SHA-384 / SHA-512.
        check(&build(None, &pq), Err(ImageError::MissingSha256Tlv));
        for other in [IMAGE_TLV_SHA384, IMAGE_TLV_SHA512] {
            let mut tlvs = Vec::from([(other, [0; 48].to_vec())]);
            tlvs.extend(pq.clone());
            check(&build(None, &tlvs), Err(ImageError::MissingSha256Tlv));
        }
        // Two, both correct, in the unprotected area; one protected plus one unprotected.
        check(
            &image(None, &[(IMAGE_TLV_SHA256, [0; 32].to_vec())]),
            Err(ImageError::MultipleSha256Tlvs),
        );
        check(
            &image(Some(&[(IMAGE_TLV_SHA256, [0; 32].to_vec())]), &[]),
            Err(ImageError::MultipleSha256Tlvs),
        );
        // Only a protected one: it is inside M, so it can never equal M.
        let mut tlvs = Vec::new();
        tlvs.extend(pq.clone());
        check(
            &build(Some(&[(IMAGE_TLV_SHA256, [0; 32].to_vec())]), &tlvs),
            Err(ImageError::DigestMismatch),
        );
        // Wrong lengths.
        for len in [0usize, 31, 33, 48] {
            let mut tlvs = Vec::from([(IMAGE_TLV_SHA256, std::vec![0; len])]);
            tlvs.extend(pq.clone());
            check(&build(None, &tlvs), Err(ImageError::InvalidSha256Tlv));
        }
        // Wrong value.
        let mut d = image(None, &[]);
        let image_ = Image::parse(&d).unwrap();
        let at = image_.hashed_range().end as usize + 4 + 4;
        d[at] ^= 1;
        check(&d, Err(ImageError::DigestMismatch));
        assert_eq!(
            backend.calls.get(),
            1,
            "only the passing image reaches the backend"
        );
    }

    #[test]
    fn security_counter_rules() {
        let keys = synth_keys();
        let backend = CountingBackend::returning(Ok(()));
        let sec = |v: &[u8]| (IMAGE_TLV_SEC_CNT, v.to_vec());
        let counter =
            |d: &[u8]| run(&backend, d, &keys, Policy::PqOnly).map(|v| v.security_counter);
        assert_eq!(counter(&image(None, &[])), Ok(None));
        assert_eq!(
            counter(&image(Some(&[sec(&7u32.to_le_bytes())]), &[])),
            Ok(Some(7))
        );
        assert_eq!(
            counter(&image(Some(&[sec(&0x1234_5678u32.to_le_bytes())]), &[])),
            Ok(Some(0x1234_5678))
        );
        // An unprotected SEC_CNT is ignored, alone or next to a protected one.
        assert_eq!(counter(&image(None, &[sec(&9u32.to_le_bytes())])), Ok(None));
        assert_eq!(
            counter(&image(
                Some(&[sec(&7u32.to_le_bytes())]),
                &[sec(&9u32.to_le_bytes())]
            )),
            Ok(Some(7))
        );
        assert_eq!(
            counter(&image(None, &[sec(&[1, 2])])),
            Ok(None),
            "an unprotected SEC_CNT is not even length-checked"
        );
        // Two protected, or the wrong length.
        assert_eq!(
            counter(&image(
                Some(&[sec(&7u32.to_le_bytes()), sec(&7u32.to_le_bytes())]),
                &[]
            )),
            Err(Error::Image(ImageError::MultipleSecurityCounters))
        );
        for len in [0usize, 2, 3, 5, 8] {
            assert_eq!(
                counter(&image(Some(&[sec(&[7; 8][..len])]), &[])),
                Err(Error::Image(ImageError::InvalidSecurityCounter)),
                "{len}"
            );
        }
        // Two protected, the first of the wrong length: Multiple is reported.
        assert_eq!(
            counter(&image(Some(&[sec(&[7, 0]), sec(&7u32.to_le_bytes())]), &[])),
            Err(Error::Image(ImageError::MultipleSecurityCounters))
        );
    }

    #[test]
    fn pq_only_ignores_classical_half_and_classical_only_ignores_pq_half() {
        let keys = synth_keys();
        let accepting = CountingBackend::returning(Ok(()));
        // Under PqOnly a KEYHASH + ED25519 pair is ignored, whatever it holds.
        let kh = (IMAGE_TLV_KEYHASH, [0x11; 32].to_vec());
        let sig = (IMAGE_TLV_ED25519, [0x22; 64].to_vec());
        for extra in [
            Vec::from([kh.clone(), sig.clone()]),
            Vec::from([sig.clone()]),
            Vec::from([kh.clone(), sig.clone(), kh.clone(), sig.clone()]),
            Vec::from([kh.clone(), (IMAGE_TLV_ED25519, [0x22; 3].to_vec())]),
        ] {
            let d = image(None, &extra);
            let verified = run(&accepting, &d, &keys, Policy::PqOnly).unwrap();
            assert_eq!(verified.ed25519_key, None);
            assert_eq!(
                verified.pq_key,
                Some(TrustedKey {
                    algorithm: Algorithm::LmsHss,
                    public_key: &LMS_PK
                })
            );
        }
        // Under ClassicalOnly the keelsign TLVs are ignored and the backend is never
        // called: the hybrid fixture with its PQ signature broken, removed, doubled, or
        // its key ID removed.
        let keys = leak_keys("keelsign-hybrid-ed25519-lms.bin");
        type Edit = fn(&mut Vec<(u16, Vec<u8>)>);
        let variants: [Edit; 4] = [
            |t| t.last_mut().unwrap().1[0] ^= 1,
            |t| t.retain(|(k, _)| *k != TLV_LMS_HSS_SIG),
            |t| {
                let last = t.last().unwrap().clone();
                t.push(last);
            },
            |t| t.retain(|(k, _)| *k != TLV_KEELSIGN_KEY_ID),
        ];
        for (i, variant) in variants.into_iter().enumerate() {
            let d = edit_unprotected(HYBRID, variant);
            let backend = CountingBackend::returning(Err(Error::SignatureInvalid));
            let result = run(&backend, &d, &keys, Policy::ClassicalOnly);
            if ed25519::is_enabled() {
                let verified = result.unwrap();
                assert_eq!(verified.pq_key, None, "{i}");
                assert_eq!(
                    verified.ed25519_key,
                    Some(Ed25519Key {
                        public_key: &ED_KEY
                    })
                );
            } else {
                assert_eq!(result, Err(Error::Ed25519(Ed25519Error::NotEnabled)));
            }
            assert_eq!(backend.calls.get(), 0, "{i}: backend never called");
            // The same image fails under PqOnly (the PQ half is checked there).
            assert!(run(&backend, &d, &keys, Policy::PqOnly).is_err(), "{i}");
        }
    }

    #[test]
    fn hybrid_checks_classical_half_before_pq_half() {
        let keys = leak_keys("keelsign-hybrid-ed25519-lms.bin");
        // Both halves broken: the Ed25519 signature flipped and the PQ signature removed.
        let both = edit_unprotected(HYBRID, |t| {
            t.iter_mut()
                .find(|(k, _)| *k == IMAGE_TLV_ED25519)
                .unwrap()
                .1[0] ^= 1;
            t.retain(|(k, _)| *k != TLV_LMS_HSS_SIG);
        });
        let backend = CountingBackend::returning(Ok(()));
        let result = run(&backend, &both, &keys, Policy::Hybrid);
        if ed25519::is_enabled() {
            assert_eq!(result, Err(Error::Ed25519(Ed25519Error::SignatureInvalid)));
        } else {
            assert_eq!(result, Err(Error::Ed25519(Ed25519Error::NotEnabled)));
        }
        assert_eq!(backend.calls.get(), 0, "the PQ half is not reached");
        // Only the PQ half broken: the PQ error.
        let pq_broken = edit_unprotected(HYBRID, |t| t.last_mut().unwrap().1[0] ^= 1);
        let backend = CountingBackend::returning(Err(Error::SignatureInvalid));
        let result = run(&backend, &pq_broken, &keys, Policy::Hybrid);
        if ed25519::is_enabled() {
            assert_eq!(result, Err(Error::SignatureInvalid));
            assert_eq!(backend.calls.get(), 1);
        } else {
            assert_eq!(result, Err(Error::Ed25519(Ed25519Error::NotEnabled)));
        }
        // Missing Ed25519 pair and missing PQ signature: the classical half is named.
        let neither = edit_unprotected(HYBRID, |t| {
            t.retain(|(k, _)| ![IMAGE_TLV_ED25519, TLV_LMS_HSS_SIG].contains(k));
        });
        let expected = if ed25519::is_enabled() {
            Ed25519Error::Missing
        } else {
            Ed25519Error::NotEnabled
        };
        assert_eq!(
            run(&backend, &neither, &keys, Policy::Hybrid).map(|_| ()),
            Err(Error::Ed25519(expected))
        );
    }

    #[test]
    fn error_precedence_is_documented_order() {
        let keys = synth_keys();
        let backend = CountingBackend::returning(Ok(()));
        let all_flags = IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_COMPRESSED_LZMA1 | IMAGE_F_NON_BOOTABLE;
        let sec = (IMAGE_TLV_SEC_CNT, 7u32.to_le_bytes().to_vec());
        let sig_pure = (IMAGE_TLV_SIG_PURE, [1].to_vec());

        // Each step removes the fault the previous step reported.
        struct Step {
            flags: u32,
            keelsign_protected: bool,
            sig_pure: bool,
            sha256: bool,
            two_sec_cnt: bool,
            bad_digest: bool,
            expected: Error,
        }
        let all = Step {
            flags: all_flags,
            keelsign_protected: true,
            sig_pure: true,
            sha256: false,
            two_sec_cnt: true,
            bad_digest: true,
            expected: Error::Image(ImageError::Encrypted),
        };
        let steps = [
            Step { ..all },
            Step {
                flags: all_flags & !IMAGE_F_ENCRYPTED_AES128,
                expected: Error::Image(ImageError::Compressed),
                ..all
            },
            Step {
                flags: IMAGE_F_NON_BOOTABLE,
                expected: Error::Image(ImageError::NonBootable),
                ..all
            },
            Step {
                flags: 0,
                expected: Error::Image(ImageError::KeelsignTlvProtected(TLV_KEELSIGN_KEY_ID)),
                ..all
            },
            Step {
                flags: 0,
                keelsign_protected: false,
                expected: Error::Image(ImageError::SigPure),
                ..all
            },
            Step {
                flags: 0,
                keelsign_protected: false,
                sig_pure: false,
                expected: Error::Image(ImageError::MissingSha256Tlv),
                ..all
            },
            Step {
                flags: 0,
                keelsign_protected: false,
                sig_pure: false,
                sha256: true,
                expected: Error::Image(ImageError::MultipleSecurityCounters),
                ..all
            },
            Step {
                flags: 0,
                keelsign_protected: false,
                sig_pure: false,
                sha256: true,
                two_sec_cnt: false,
                expected: Error::Image(ImageError::DigestMismatch),
                ..all
            },
            Step {
                flags: 0,
                keelsign_protected: false,
                sig_pure: false,
                sha256: true,
                two_sec_cnt: false,
                bad_digest: false,
                // Under PqOnly, with no PQ TLVs: the PQ half's first error.
                expected: Error::MissingPqSignature,
            },
        ];
        for (i, step) in steps.iter().enumerate() {
            let mut protected = Vec::from([sec.clone()]);
            if step.two_sec_cnt {
                protected.push(sec.clone());
            }
            if step.keelsign_protected {
                protected.push((TLV_KEELSIGN_KEY_ID, [0; 16].to_vec()));
            }
            let mut unprotected = Vec::new();
            if step.sha256 {
                unprotected.push((IMAGE_TLV_SHA256, [0; 32].to_vec()));
            }
            if step.sig_pure {
                unprotected.push(sig_pure.clone());
            }
            let mut d = synth(
                Some(
                    &protected
                        .iter()
                        .map(|(t, v)| (*t, v.as_slice()))
                        .collect::<Vec<_>>(),
                ),
                &unprotected
                    .iter()
                    .map(|(t, v)| (*t, v.as_slice()))
                    .collect::<Vec<_>>(),
            );
            set_u32(&mut d, 16, step.flags);
            let mut d = finish(d);
            if step.bad_digest && step.sha256 {
                let at = Image::parse(&d).unwrap().hashed_range().end as usize + 8;
                d[at] ^= 1;
            }
            assert_eq!(
                run(&backend, &d, &keys, Policy::PqOnly).map(|_| ()),
                Err(step.expected),
                "step {i}"
            );
            // Step 0: without the feature, the Ed25519 policies fail before all of these.
            if !ed25519::is_enabled() {
                for policy in [Policy::ClassicalOnly, Policy::Hybrid] {
                    assert_eq!(
                        run(&backend, &d, &keys, policy).map(|_| ()),
                        Err(Error::Ed25519(Ed25519Error::NotEnabled)),
                        "step {i} {policy:?}"
                    );
                }
            }
        }
        // Step 8 before step 9: the last image under Hybrid names the classical half.
        let last = finish(synth(
            Some(&[(IMAGE_TLV_SEC_CNT, &7u32.to_le_bytes()[..])]),
            &[(IMAGE_TLV_SHA256, &[0; 32][..])],
        ));
        let expected = if ed25519::is_enabled() {
            Ed25519Error::Missing
        } else {
            Ed25519Error::NotEnabled
        };
        assert_eq!(
            run(&backend, &last, &keys, Policy::Hybrid).map(|_| ()),
            Err(Error::Ed25519(expected))
        );
        // Step 1 before step 2: a parse error wins over the flags, and a TLV buffer too
        // small for the TLV areas is TlvAreaTooLarge.
        let mut bad = last.clone();
        set_u32(&mut bad, 16, all_flags);
        bad[0] ^= 1;
        assert_eq!(
            run(&backend, &bad, &keys, Policy::PqOnly).map(|_| ()),
            Err(Error::Parse(ParseError::BadMagic))
        );
        let mut reader: &[u8] = &last;
        assert_eq!(
            verify_with(
                &backend,
                &mut reader,
                &keys,
                Policy::PqOnly,
                &mut [0; 8],
                &mut [0; 8]
            )
            .map(|_| ()),
            Err(Error::TlvAreaTooLarge)
        );
        // Step 7: an empty chunk buffer comes after the image rules and before the
        // digest comparison.
        let mut reader: &[u8] = &last;
        assert_eq!(
            verify_with(
                &backend,
                &mut reader,
                &keys,
                Policy::PqOnly,
                &mut [0; 64],
                &mut []
            )
            .map(|_| ()),
            Err(Error::ChunkBufferEmpty)
        );
        let mut flagged = last.clone();
        set_u32(&mut flagged, 16, IMAGE_F_NON_BOOTABLE);
        let mut reader: &[u8] = &flagged;
        assert_eq!(
            verify_with(
                &backend,
                &mut reader,
                &keys,
                Policy::PqOnly,
                &mut [0; 64],
                &mut []
            )
            .map(|_| ()),
            Err(Error::Image(ImageError::NonBootable))
        );
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn verify_with_cnsa_2_0_refuses_the_hss2_image_under_pq_only() {
        for (name, data) in FIXTURES {
            let Some((Algorithm::LmsHss, _)) = manifest_key(name) else {
                continue;
            };
            if name == "keelsign-dual-pq-invalid.bin" {
                continue;
            }
            let keys = leak_keys(name);
            let mut reader = data;
            let strict = verify_with(
                &DefaultBackend::cnsa_2_0(),
                &mut reader,
                &keys,
                Policy::PqOnly,
                &mut [0; 4096],
                &mut [0; 256],
            );
            let default = run(&DefaultBackend::new(), data, &keys, Policy::PqOnly);
            assert!(default.is_ok(), "{name}");
            if name == "keelsign-hss2-m32-h5h5.bin" {
                assert_eq!(strict, Err(Error::UnsupportedParameterSet), "{name}");
            } else {
                assert_eq!(strict, default, "{name}");
            }
        }
    }

    #[test]
    fn verify_and_verify_with_default_agree_on_every_fixture() {
        let mut ok = 0;
        for (name, data) in FIXTURES {
            let keys = leak_keys(name);
            for &policy in Policy::ALL {
                let mut reader = data;
                let a = verify(&mut reader, &keys, policy, &mut [0; 4096], &mut [0; 256]);
                let b = run(&DefaultBackend::new(), data, &keys, policy);
                assert_eq!(a, b, "{name} {policy:?}");
                ok += usize::from(a.is_ok());
            }
        }
        // PqOnly: the four LMS/HSS images; with the feature, also the Ed25519 goldens and
        // the hybrid image under ClassicalOnly, and the hybrid image under Hybrid.
        assert_eq!(ok, if ed25519::is_enabled() { 4 + 4 + 1 } else { 4 });
    }
}
