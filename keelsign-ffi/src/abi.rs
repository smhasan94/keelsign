//! The C ABI: the only module of this crate where `unsafe` is allowed. Every `unsafe`
//! block carries a `// SAFETY:` comment naming the part of the caller's contract it
//! relies on.

use core::{ptr, slice};

use keelsign_verify::image::Image;
use keelsign_verify::lms;
use keelsign_verify::{
    Algorithm, Ed25519Key, Policy, TrustedKey, TrustedKeys, VerifiedImage, image_digest, verify,
};

use crate::status::{keelsign_status_t, keyset_status, status_of};
use crate::{
    KEELSIGN_ALG_ED25519, KEELSIGN_ALG_LMS_HSS, KEELSIGN_ALG_MLDSA44, KEELSIGN_ALG_MLDSA65,
    KEELSIGN_CHUNK_LEN, KEELSIGN_MAX_ED25519_KEYS, KEELSIGN_MAX_PQ_KEYS, KEELSIGN_NO_KEY,
    KEELSIGN_POLICY_CLASSICAL_ONLY, KEELSIGN_POLICY_HYBRID, KEELSIGN_POLICY_PQ_ONLY,
    KEELSIGN_TLV_BUF_LEN, keelsign_alg_t, keelsign_key_t, keelsign_policy_t, keelsign_result_t,
};

use keelsign_status_t::{
    KEELSIGN_ERR_IMAGE_TOO_LARGE, KEELSIGN_ERR_INVALID_ALGORITHM, KEELSIGN_ERR_INVALID_POLICY,
    KEELSIGN_ERR_KEY_LENGTH, KEELSIGN_ERR_NULL_POINTER, KEELSIGN_ERR_TOO_MANY_KEYS, KEELSIGN_OK,
};

/// Whether `len` is a raw public-key length of `algorithm`: FIPS 204 1312 / 1952 bytes,
/// HSS 52 (L=1) or 60 bytes. Checked per key, before a slice is formed; the key set
/// then checks the LMS/HSS typecodes.
fn pq_key_len_ok(algorithm: Algorithm, len: usize) -> bool {
    match algorithm.public_key_len() {
        Some(expected) => len == expected,
        None => lms::PUBLIC_KEY_LENS.contains(&len),
    }
}

/// Placeholder for the unused Ed25519 key slots.
static NO_ED25519_KEY: [u8; 32] = [0; 32];

/// Verify the MCUboot image `image[0..len)` under `policy` with the trusted `keys`.
///
/// Returns `KEELSIGN_OK` and, if `out` is not NULL, writes what was verified to `*out`.
/// On any error `*out` is left untouched.
///
/// Arguments are checked in this order, the first failure is returned:
/// `image` NULL or `keys` NULL with `n_keys > 0` (`KEELSIGN_ERR_NULL_POINTER`);
/// `len > UINT32_MAX` (`KEELSIGN_ERR_IMAGE_TOO_LARGE`); `policy`
/// (`KEELSIGN_ERR_INVALID_POLICY`); then each key in array order: its `alg`
/// (`KEELSIGN_ERR_INVALID_ALGORITHM`), its `key` pointer (`KEELSIGN_ERR_NULL_POINTER`),
/// the per-kind limit `KEELSIGN_MAX_PQ_KEYS` / `KEELSIGN_MAX_ED25519_KEYS`
/// (`KEELSIGN_ERR_TOO_MANY_KEYS`) and its length (`KEELSIGN_ERR_KEY_LENGTH`); then the
/// key set as a whole (duplicates, LMS/HSS key format); then the image. `len == 0` gives
/// `KEELSIGN_ERR_PARSE_TRUNCATED`.
///
/// `pq_key_index` / `ed25519_key_index` in `*out` are indices into `keys`, found by
/// pointer identity, so they name the caller's slot whatever the key order.
///
/// # Safety
///
/// - `image` is non-NULL and readable for `len` bytes, at any alignment. A `len` above
///   `UINT32_MAX`, or on a 32-bit target above `PTRDIFF_MAX`, is rejected with
///   `KEELSIGN_ERR_IMAGE_TOO_LARGE` before anything is read.
/// - `keys` is NULL only if `n_keys` is 0; otherwise it points to `n_keys` consecutive
///   `keelsign_key_t` (any alignment).
/// - Each `keys[i].key` is non-NULL and readable for `keys[i].key_len` bytes.
/// - `out` is NULL or writable for one `keelsign_result_t` (any alignment), and does
///   not overlap `image`, `keys` or any key's bytes.
/// - None of this memory is written by anyone else during the call. Nothing is retained
///   after the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keelsign_verify(
    image: *const u8,
    len: usize,
    keys: *const keelsign_key_t,
    n_keys: usize,
    policy: keelsign_policy_t,
    out: *mut keelsign_result_t,
) -> keelsign_status_t {
    if image.is_null() || (keys.is_null() && n_keys != 0) {
        return KEELSIGN_ERR_NULL_POINTER;
    }
    if !len_fits(len) {
        return KEELSIGN_ERR_IMAGE_TOO_LARGE;
    }
    let Some(policy) = policy_of(policy) else {
        return KEELSIGN_ERR_INVALID_POLICY;
    };

    let mut pq = [TrustedKey {
        algorithm: Algorithm::LmsHss,
        public_key: &[],
    }; KEELSIGN_MAX_PQ_KEYS];
    let mut pq_slots = [KEELSIGN_NO_KEY; KEELSIGN_MAX_PQ_KEYS];
    let mut ed = [Ed25519Key {
        public_key: &NO_ED25519_KEY,
    }; KEELSIGN_MAX_ED25519_KEYS];
    let mut ed_slots = [KEELSIGN_NO_KEY; KEELSIGN_MAX_ED25519_KEYS];
    let (mut n_pq, mut n_ed) = (0usize, 0usize);
    // At most KEELSIGN_MAX_PQ_KEYS + KEELSIGN_MAX_ED25519_KEYS + 1 entries are ever read:
    // the next one after both limits are full fails with KEELSIGN_ERR_TOO_MANY_KEYS.
    for i in 0..n_keys {
        // SAFETY: `n_keys > 0` here, so `keys` is non-NULL (checked above) and points to
        // `n_keys` consecutive entries (contract); `i < n_keys` keeps `keys.add(i)` inside
        // that array. `read_unaligned` copies the entry at any alignment.
        let key = unsafe { keys.add(i).read_unaligned() };
        let algorithm = match algorithm_of(key.alg) {
            Some(algorithm) => algorithm,
            None => return KEELSIGN_ERR_INVALID_ALGORITHM,
        };
        if key.key.is_null() {
            return KEELSIGN_ERR_NULL_POINTER;
        }
        // At most 17 iterations run (see above), so the index fits.
        let Ok(slot) = u32::try_from(i) else {
            return KEELSIGN_ERR_TOO_MANY_KEYS;
        };
        match algorithm {
            KeyKind::Pq(algorithm) => {
                let (Some(entry), Some(index)) = (pq.get_mut(n_pq), pq_slots.get_mut(n_pq)) else {
                    return KEELSIGN_ERR_TOO_MANY_KEYS;
                };
                if !pq_key_len_ok(algorithm, key.key_len) {
                    return KEELSIGN_ERR_KEY_LENGTH;
                }
                // SAFETY: `key.key` is non-NULL (checked above) and readable for
                // `key.key_len` bytes that nobody writes during the call (contract);
                // `key_len <= 1952` (checked above) keeps the slice far below
                // `isize::MAX`; `u8` has no
                // alignment requirement. The slice does not outlive the call.
                let public_key = unsafe { slice::from_raw_parts(key.key, key.key_len) };
                *entry = TrustedKey {
                    algorithm,
                    public_key,
                };
                *index = slot;
                n_pq += 1;
            }
            KeyKind::Ed25519 => {
                let (Some(entry), Some(index)) = (ed.get_mut(n_ed), ed_slots.get_mut(n_ed)) else {
                    return KEELSIGN_ERR_TOO_MANY_KEYS;
                };
                if key.key_len != 32 {
                    return KEELSIGN_ERR_KEY_LENGTH;
                }
                // SAFETY: `key.key` is non-NULL (checked above) and readable for
                // `key.key_len == 32` bytes that nobody writes during the call (contract);
                // `[u8; 32]` has alignment 1. The reference does not outlive the call.
                let public_key = unsafe { &*key.key.cast::<[u8; 32]>() };
                *entry = Ed25519Key { public_key };
                *index = slot;
                n_ed += 1;
            }
        }
    }
    let pq = pq.get(..n_pq).unwrap_or_default();
    let ed = ed.get(..n_ed).unwrap_or_default();
    let set = match TrustedKeys::<KEELSIGN_MAX_PQ_KEYS, KEELSIGN_MAX_ED25519_KEYS>::with_ed25519(
        pq, ed,
    ) {
        Ok(set) => set,
        Err(e) => return keyset_status(e),
    };

    // SAFETY: `image` is non-NULL (checked above) and readable for `len` bytes that
    // nobody writes during the call (contract); `len_fits` keeps `len <= isize::MAX`;
    // `u8` has no alignment requirement. The slice does not outlive the call.
    let mut reader: &[u8] = unsafe { slice::from_raw_parts(image, len) };
    let mut tlv_buf = [0u8; KEELSIGN_TLV_BUF_LEN];
    let mut chunk = [0u8; KEELSIGN_CHUNK_LEN];
    let verified = match verify(&mut reader, &set, policy, &mut tlv_buf, &mut chunk) {
        Ok(verified) => verified,
        Err(e) => return status_of(e),
    };
    if !out.is_null() {
        let result = result_of(&verified, pq, &pq_slots, ed, &ed_slots);
        // SAFETY: `out` is non-NULL (checked) and writable for one `keelsign_result_t`
        // (contract); `write_unaligned` accepts any alignment and the old value is plain
        // data with nothing to drop.
        unsafe { out.write_unaligned(result) };
    }
    KEELSIGN_OK
}

/// Compute the image digest `M` of `image[0..len)` (SHA-256 of the header, the body and
/// the protected TLV area, as both signatures cover it) and write its 32 bytes to
/// `out_digest`. The image is parsed but no signature is checked.
///
/// Returns `KEELSIGN_ERR_NULL_POINTER` if either pointer is NULL,
/// `KEELSIGN_ERR_IMAGE_TOO_LARGE` if `len > UINT32_MAX`, else a parse or read error or
/// `KEELSIGN_OK`. `out_digest` is written only on `KEELSIGN_OK`.
///
/// # Safety
///
/// - `image` is non-NULL and readable for `len` bytes, at any alignment. A `len` above
///   `UINT32_MAX`, or on a 32-bit target above `PTRDIFF_MAX`, is rejected with
///   `KEELSIGN_ERR_IMAGE_TOO_LARGE` before anything is read.
/// - `out_digest` is non-NULL and writable for 32 bytes, and does not overlap `image`.
/// - None of this memory is written by anyone else during the call. Nothing is retained
///   after the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keelsign_digest(
    image: *const u8,
    len: usize,
    out_digest: *mut u8,
) -> keelsign_status_t {
    if image.is_null() || out_digest.is_null() {
        return KEELSIGN_ERR_NULL_POINTER;
    }
    if !len_fits(len) {
        return KEELSIGN_ERR_IMAGE_TOO_LARGE;
    }
    // SAFETY: `image` is non-NULL (checked above) and readable for `len` bytes that
    // nobody writes during the call (contract); `len_fits` keeps `len <= isize::MAX`;
    // `u8` has no alignment requirement. The slice does not outlive the call.
    let mut reader: &[u8] = unsafe { slice::from_raw_parts(image, len) };
    let mut tlv_buf = [0u8; KEELSIGN_TLV_BUF_LEN];
    let mut chunk = [0u8; KEELSIGN_CHUNK_LEN];
    let parsed = match Image::read_from(&mut reader, &mut tlv_buf) {
        Ok(parsed) => parsed,
        Err(e) => return status_of(e),
    };
    let digest = match image_digest(&mut reader, &parsed, &mut chunk) {
        Ok(digest) => digest,
        Err(e) => return status_of(e),
    };
    // SAFETY: `out_digest` is non-NULL (checked above) and writable for 32 bytes
    // (contract), which cannot overlap the local `digest`; `u8` has no alignment
    // requirement.
    unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), out_digest, digest.len()) };
    KEELSIGN_OK
}

/// Whether `len` is a valid image length: at most `UINT32_MAX` (MCUboot's sizes are 32
/// bits) and at most `isize::MAX` (the most a slice may span, on 32-bit targets too).
fn len_fits(len: usize) -> bool {
    u32::try_from(len).is_ok() && isize::try_from(len).is_ok()
}

fn policy_of(policy: keelsign_policy_t) -> Option<Policy> {
    match policy {
        KEELSIGN_POLICY_CLASSICAL_ONLY => Some(Policy::ClassicalOnly),
        KEELSIGN_POLICY_PQ_ONLY => Some(Policy::PqOnly),
        KEELSIGN_POLICY_HYBRID => Some(Policy::Hybrid),
        _ => None,
    }
}

/// Which key array a `keelsign_key_t` goes into.
#[derive(Clone, Copy)]
enum KeyKind {
    Pq(Algorithm),
    Ed25519,
}

fn algorithm_of(alg: keelsign_alg_t) -> Option<KeyKind> {
    match alg {
        KEELSIGN_ALG_MLDSA44 => Some(KeyKind::Pq(Algorithm::MlDsa44)),
        KEELSIGN_ALG_MLDSA65 => Some(KeyKind::Pq(Algorithm::MlDsa65)),
        KEELSIGN_ALG_LMS_HSS => Some(KeyKind::Pq(Algorithm::LmsHss)),
        KEELSIGN_ALG_ED25519 => Some(KeyKind::Ed25519),
        _ => None,
    }
}

/// The C view of a verified image. The key indices are found by pointer identity (the
/// verifier hands back the trusted key it used, borrowing the caller's bytes).
fn result_of(
    verified: &VerifiedImage<'_>,
    pq: &[TrustedKey<'_>],
    pq_slots: &[u32],
    ed: &[Ed25519Key<'_>],
    ed_slots: &[u32],
) -> keelsign_result_t {
    let pq_key_index = verified
        .pq_key
        .and_then(|used| {
            pq.iter()
                .zip(pq_slots)
                .find(|(k, _)| {
                    k.algorithm == used.algorithm && ptr::eq(k.public_key, used.public_key)
                })
                .map(|(_, slot)| *slot)
        })
        .unwrap_or(KEELSIGN_NO_KEY);
    let ed25519_key_index = verified
        .ed25519_key
        .and_then(|used| {
            ed.iter()
                .zip(ed_slots)
                .find(|(k, _)| ptr::eq(k.public_key, used.public_key))
                .map(|(_, slot)| *slot)
        })
        .unwrap_or(KEELSIGN_NO_KEY);
    keelsign_result_t {
        major: verified.version.major,
        minor: verified.version.minor,
        revision: verified.version.revision,
        build_num: verified.version.build_num,
        has_security_counter: u8::from(verified.security_counter.is_some()),
        security_counter: verified.security_counter.unwrap_or(0),
        image_len: verified.image_len,
        digest: verified.digest,
        pq_key_index,
        ed25519_key_index,
    }
}

/// Panics cannot unwind across the C ABI and must not reach formatting code: trap.
/// The `PanicInfo` is never read, so no message is formatted.
#[cfg(all(not(test), not(panic = "unwind"), target_os = "none"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        // SAFETY: `udf` raises an undefined-instruction exception (HardFault on
        // Cortex-M); it touches no memory and no stack.
        unsafe { core::arch::asm!("udf #0", options(nomem, nostack)) };
    }
}

/// On a hosted target (the C harness, host tools) a panic aborts the process.
#[cfg(all(not(test), not(panic = "unwind"), not(target_os = "none")))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: libc's `abort(void)` takes no arguments, never returns and is safe to call
    // from any state, so declaring it `safe fn abort() -> !` is sound.
    unsafe extern "C" {
        safe fn abort() -> !;
    }
    abort()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::boxed::Box;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use keelsign_verify::{ed25519, mldsa};
    use policy_kat::{Case, ED25519_TEST_KEY, Expect, Fixture, POLICY_TARGET};

    use super::*;
    use crate::status::keelsign_status_t::*;

    /// MANIFEST.json of the image fixtures (digests, parse verdicts).
    const MANIFEST: &str = include_str!("../../tests/fixtures/images/MANIFEST.json");

    /// The 200 KB Ed25519 image: in MANIFEST.json but not in the on-target index.
    const IMAGE_200K: &[u8] =
        include_bytes!("../../tests/fixtures/images/mcuboot-ed25519-200k.bin");

    /// A result whose every byte is 0xA5, to show `out` was not written.
    fn sentinel() -> keelsign_result_t {
        keelsign_result_t {
            major: 0xA5,
            minor: 0xA5,
            revision: 0xA5A5,
            build_num: 0xA5A5_A5A5,
            has_security_counter: 0xA5,
            security_counter: 0xA5A5_A5A5,
            image_len: 0xA5A5_A5A5,
            digest: [0xA5; 32],
            pq_key_index: 0xA5A5_A5A5,
            ed25519_key_index: 0xA5A5_A5A5,
        }
    }

    fn c_alg(algorithm: Algorithm) -> keelsign_alg_t {
        match algorithm {
            Algorithm::MlDsa44 => KEELSIGN_ALG_MLDSA44,
            Algorithm::MlDsa65 => KEELSIGN_ALG_MLDSA65,
            Algorithm::LmsHss => KEELSIGN_ALG_LMS_HSS,
            other => panic!("no C algorithm for {other:?}"),
        }
    }

    fn c_policy(policy: Policy) -> keelsign_policy_t {
        match policy {
            Policy::ClassicalOnly => KEELSIGN_POLICY_CLASSICAL_ONLY,
            Policy::PqOnly => KEELSIGN_POLICY_PQ_ONLY,
            Policy::Hybrid => KEELSIGN_POLICY_HYBRID,
            other => panic!("no C policy for {other:?}"),
        }
    }

    fn key(alg: keelsign_alg_t, bytes: &[u8]) -> keelsign_key_t {
        keelsign_key_t {
            alg,
            key: bytes.as_ptr(),
            key_len: bytes.len(),
        }
    }

    /// `keelsign_verify` on live slices, `out` pre-filled with [`sentinel`].
    fn call(
        image: &[u8],
        keys: &[keelsign_key_t],
        policy: keelsign_policy_t,
    ) -> (keelsign_status_t, keelsign_result_t) {
        let mut out = sentinel();
        // SAFETY: `image` and `keys` are live slices of the lengths passed, every key was
        // built by `key` from a slice the caller keeps alive, and `out` is a live local.
        let status = unsafe {
            keelsign_verify(
                image.as_ptr(),
                image.len(),
                keys.as_ptr(),
                keys.len(),
                policy,
                &mut out,
            )
        };
        (status, out)
    }

    /// `keelsign_digest` on a live slice, the output pre-filled with 0xA5.
    fn digest(image: &[u8]) -> (keelsign_status_t, [u8; 32]) {
        let mut out = [0xA5u8; 32];
        // SAFETY: `image` is a live slice of the length passed and `out` a live 32-byte
        // local.
        let status = unsafe { keelsign_digest(image.as_ptr(), image.len(), out.as_mut_ptr()) };
        (status, out)
    }

    /// The status code of a policy-matrix verdict.
    fn expected_status(expect: Expect) -> keelsign_status_t {
        match expect {
            Expect::Ok => KEELSIGN_OK,
            Expect::ParseBadMagic => KEELSIGN_ERR_PARSE_BAD_MAGIC,
            Expect::MissingPqSignature => KEELSIGN_ERR_MISSING_PQ_SIGNATURE,
            Expect::MissingKeyId => KEELSIGN_ERR_MISSING_KEY_ID,
            Expect::MultiplePqSignatures => KEELSIGN_ERR_MULTIPLE_PQ_SIGNATURES,
            Expect::SignatureInvalid => KEELSIGN_ERR_SIGNATURE_INVALID,
            Expect::UnsupportedMlDsa44 | Expect::UnsupportedMlDsa65 => {
                KEELSIGN_ERR_UNSUPPORTED_ALGORITHM
            }
            Expect::Ed25519Missing => KEELSIGN_ERR_ED25519_MISSING,
            Expect::Ed25519Multiple => KEELSIGN_ERR_ED25519_MULTIPLE,
            Expect::Ed25519Unpaired => KEELSIGN_ERR_ED25519_UNPAIRED,
            Expect::Ed25519InvalidSignatureLength => KEELSIGN_ERR_ED25519_INVALID_SIGNATURE_LENGTH,
            Expect::Ed25519SignatureInvalid => KEELSIGN_ERR_ED25519_SIGNATURE_INVALID,
            Expect::ImageEncrypted => KEELSIGN_ERR_IMAGE_ENCRYPTED,
            Expect::ImageCompressed => KEELSIGN_ERR_IMAGE_COMPRESSED,
            Expect::ImageNonBootable => KEELSIGN_ERR_IMAGE_NON_BOOTABLE,
            Expect::ImageKeelsignTlvProtectedKeyId => KEELSIGN_ERR_IMAGE_KEELSIGN_TLV_PROTECTED,
            Expect::ImageSigPure => KEELSIGN_ERR_IMAGE_SIG_PURE,
            Expect::ImageMissingSha256Tlv => KEELSIGN_ERR_IMAGE_MISSING_SHA256_TLV,
            Expect::ImageMultipleSha256Tlvs => KEELSIGN_ERR_IMAGE_MULTIPLE_SHA256_TLVS,
            Expect::ImageMultipleSecurityCounters => KEELSIGN_ERR_IMAGE_MULTIPLE_SECURITY_COUNTERS,
            Expect::ImageDigestMismatch => KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH,
            Expect::MalformedSignature => KEELSIGN_ERR_MALFORMED_SIGNATURE,
            Expect::KeyNotTrusted => KEELSIGN_ERR_KEY_NOT_TRUSTED,
        }
    }

    fn cases() -> Vec<Case<'static>> {
        let fixture = Fixture::parse(POLICY_TARGET).unwrap();
        let cases: Vec<Case<'static>> = fixture.cases().collect::<Result<_, _>>().unwrap();
        assert_eq!(cases.len(), 52);
        cases
    }

    fn case(name: &str) -> Case<'static> {
        Fixture::parse(POLICY_TARGET)
            .unwrap()
            .case(name)
            .unwrap_or_else(|| panic!("{name} is not in the policy matrix"))
    }

    /// The case's post-quantum key (if any) followed by the Ed25519 test key, as the
    /// policy-matrix runner trusts them.
    fn keys_for(case: &Case<'static>) -> Vec<keelsign_key_t> {
        let mut keys = Vec::new();
        if let Some(algorithm) = case.algorithm {
            keys.push(key(c_alg(algorithm), case.public_key));
        }
        keys.push(key(KEELSIGN_ALG_ED25519, &ED25519_TEST_KEY));
        keys
    }

    /// One cell through the C ABI: the status agrees with `keelsign_verify::verify` and
    /// with the matrix verdict, `out` matches the `VerifiedImage` (or is untouched).
    fn check_cell(case: &Case<'static>, policy: Policy) {
        let image = policy_kat::image(case.name).unwrap();
        let keys = keys_for(case);
        let (status, out) = call(image, &keys, c_policy(policy));

        let set = policy_kat::trusted_keys(case).unwrap();
        let mut tlv_buf = [0u8; KEELSIGN_TLV_BUF_LEN];
        let mut chunk = [0u8; KEELSIGN_CHUNK_LEN];
        let mut reader = image;
        let direct = verify(&mut reader, &set, policy, &mut tlv_buf, &mut chunk);
        let direct_status = direct.map_or_else(status_of, |_| KEELSIGN_OK);
        let cell = format!("{} under {policy:?}", case.name);
        assert_eq!(
            status, direct_status,
            "{cell}: C ABI vs keelsign_verify::verify"
        );

        let matrix = if policy.requires_ed25519() && !ed25519::is_enabled() {
            KEELSIGN_ERR_ED25519_NOT_ENABLED
        } else {
            expected_status(case.expect(policy, mldsa::is_enabled()).unwrap())
        };
        assert_eq!(status, matrix, "{cell}: policy matrix verdict");

        match direct {
            Ok(v) => {
                let pq_index = if policy.requires_pq() {
                    0
                } else {
                    KEELSIGN_NO_KEY
                };
                let ed_slot = u32::from(case.algorithm.is_some());
                let ed_index = if policy.requires_ed25519() {
                    ed_slot
                } else {
                    KEELSIGN_NO_KEY
                };
                let want = keelsign_result_t {
                    major: v.version.major,
                    minor: v.version.minor,
                    revision: v.version.revision,
                    build_num: v.version.build_num,
                    has_security_counter: u8::from(v.security_counter.is_some()),
                    security_counter: v.security_counter.unwrap_or(0),
                    image_len: v.image_len,
                    digest: v.digest,
                    pq_key_index: pq_index,
                    ed25519_key_index: ed_index,
                };
                assert_eq!(out, want, "{cell}: result");
            }
            Err(_) => assert_eq!(out, sentinel(), "{cell}: out written on failure"),
        }
    }

    /// AC2 / TP1: every cell of the SHA-46 policy matrix (52 images × 3 policies) gives
    /// the same verdict through the C ABI as through `keelsign_verify::verify`, and the
    /// verdict the matrix records for this build's features.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "the full matrix is too slow under miri; see miri_subset_of_policy_matrix"
    )]
    fn verify_agrees_with_keelsign_verify_on_every_policy_matrix_case() {
        let mut cells = 0;
        for case in cases() {
            for &policy in Policy::ALL {
                check_cell(&case, policy);
                cells += 1;
            }
        }
        assert_eq!(cells, 52 * 3);
    }

    /// AC4: a slice of the matrix that miri runs. Under miri only cells that need no
    /// signature arithmetic (each full LMS/HSS, Ed25519 or ML-DSA verify takes minutes
    /// there; `pointer_contract_is_honoured_under_miri` runs the one successful LMS/HSS
    /// verify): the whole image read and hashed (DigestMismatch), a parse failure, the
    /// Ed25519 half's TLV checks and an ML-DSA key in the key set. Outside miri the
    /// successful LMS/HSS, Ed25519, hybrid and (with `ml-dsa`) ML-DSA-44 cells as well.
    #[test]
    fn miri_subset_of_policy_matrix() {
        let mut cells = std::vec![
            ("keelsign-hybrid-bad-body.bin", Policy::PqOnly),
            ("keelsign-hybrid-bad-body.bin", Policy::ClassicalOnly),
            ("rejected/mcuboot-ed25519-bigendian.bin", Policy::PqOnly),
            ("keelsign-hybrid-short-ed25519.bin", Policy::ClassicalOnly),
            ("keelsign-hybrid-two-ed25519.bin", Policy::ClassicalOnly),
            ("mcuboot-rsa2048.bin", Policy::ClassicalOnly),
            ("keelsign-mldsa44-bad-key-id.bin", Policy::PqOnly),
            ("keelsign-mldsa44-bad-body.bin", Policy::PqOnly),
        ];
        if !cfg!(miri) {
            cells.extend([
                ("keelsign-lms-m32-h5.bin", Policy::PqOnly),
                ("mcuboot-ed25519.bin", Policy::ClassicalOnly),
                ("keelsign-hybrid-ed25519-lms.bin", Policy::Hybrid),
            ]);
            if mldsa::is_enabled() {
                cells.push(("keelsign-mldsa44.bin", Policy::PqOnly));
            }
        }
        for (name, policy) in cells {
            check_cell(&case(name), policy);
        }
    }

    /// The `field` string value of output `name` in MANIFEST.json.
    fn manifest_field(name: &str, field: &str) -> String {
        let outputs = &MANIFEST[MANIFEST.find("\"outputs\": {").unwrap()..];
        let start = outputs
            .find(&format!("\n    \"{name}\": {{"))
            .unwrap_or_else(|| panic!("MANIFEST.json has no output {name}"));
        let object = &outputs[start..];
        let end = object.find("\n    }").unwrap();
        let object = &object[..end];
        let needle = format!("\"{field}\": \"");
        let at = object
            .find(&needle)
            .unwrap_or_else(|| panic!("MANIFEST.json {name} has no {field}"))
            + needle.len();
        object[at..].split('"').next().unwrap().to_owned()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// AC2: `keelsign_digest` gives MANIFEST.json's `digest_hex` for every image that
    /// parses, and the parse error for the one that does not.
    #[test]
    #[cfg_attr(miri, ignore = "hashes 53 images; too slow under miri")]
    fn digest_matches_the_manifest_digest_for_every_image() {
        let mut images: Vec<(&str, &[u8])> = policy_kat::IMAGES.to_vec();
        images.push(("mcuboot-ed25519-200k.bin", IMAGE_200K));
        assert_eq!(images.len(), 53);
        for (name, image) in images {
            let (status, out) = digest(image);
            match manifest_field(name, "expect_parse").as_str() {
                "Ok" => {
                    assert_eq!(status, KEELSIGN_OK, "{name}");
                    assert_eq!(hex(&out), manifest_field(name, "digest_hex"), "{name}");
                }
                "BadMagic" => {
                    assert_eq!(status, KEELSIGN_ERR_PARSE_BAD_MAGIC, "{name}");
                    assert_eq!(out, [0xA5; 32], "{name}: written on failure");
                }
                other => panic!("{name}: unexpected expect_parse {other}"),
            }
        }
    }

    /// The image's PQ key plus distinct other valid keys of the same kind, for rotation.
    fn distinct_lms_keys() -> Vec<&'static [u8]> {
        let mut keys: Vec<&'static [u8]> = Vec::new();
        for case in cases() {
            if case.algorithm == Some(Algorithm::LmsHss) && !keys.contains(&case.public_key) {
                keys.push(case.public_key);
            }
        }
        assert!(keys.len() >= 2, "the matrix has at least two LMS/HSS keys");
        keys
    }

    /// TP1: `pq_key_index` and `ed25519_key_index` name the caller's slot in `keys`
    /// whatever the order: the signing keys are rotated through every position among an
    /// untrusted LMS/HSS key and the same bytes again at another address.
    #[test]
    #[cfg_attr(miri, ignore = "18 hybrid verifies; too slow under miri")]
    fn key_index_names_the_callers_slot_after_rotation() {
        let case = case("keelsign-hybrid-ed25519-lms.bin");
        let image = policy_kat::image(case.name).unwrap();
        let other = *distinct_lms_keys()
            .iter()
            .find(|k| **k != case.public_key)
            .unwrap();
        let signer = key(KEELSIGN_ALG_LMS_HSS, case.public_key);
        let ed = key(KEELSIGN_ALG_ED25519, &ED25519_TEST_KEY);
        let decoy = key(KEELSIGN_ALG_LMS_HSS, other);
        let orders: [[keelsign_key_t; 3]; 6] = [
            [signer, ed, decoy],
            [signer, decoy, ed],
            [ed, signer, decoy],
            [ed, decoy, signer],
            [decoy, signer, ed],
            [decoy, ed, signer],
        ];
        for keys in orders {
            let slot_of = |wanted: &keelsign_key_t| {
                u32::try_from(
                    keys.iter()
                        .position(|k| ptr::eq(k.key, wanted.key))
                        .unwrap(),
                )
                .unwrap()
            };
            let (status, out) = call(image, &keys, KEELSIGN_POLICY_HYBRID);
            assert_eq!(status, KEELSIGN_OK);
            assert_eq!(out.pq_key_index, slot_of(&signer));
            assert_eq!(out.ed25519_key_index, slot_of(&ed));

            let (status, out) = call(image, &keys, KEELSIGN_POLICY_PQ_ONLY);
            assert_eq!(status, KEELSIGN_OK);
            assert_eq!(out.pq_key_index, slot_of(&signer));
            assert_eq!(out.ed25519_key_index, KEELSIGN_NO_KEY);

            let (status, out) = call(image, &keys, KEELSIGN_POLICY_CLASSICAL_ONLY);
            assert_eq!(status, KEELSIGN_OK);
            assert_eq!(out.pq_key_index, KEELSIGN_NO_KEY);
            assert_eq!(out.ed25519_key_index, slot_of(&ed));
        }
        // The signing key's bytes at a second address are a duplicate key ID.
        let copy: Vec<u8> = case.public_key.to_vec();
        let keys = [decoy, key(KEELSIGN_ALG_LMS_HSS, &copy), signer];
        assert_eq!(
            call(image, &keys, KEELSIGN_POLICY_PQ_ONLY).0,
            KEELSIGN_ERR_DUPLICATE_KEY
        );
        // Only the copy trusted: index 1, the copy's slot.
        let keys = [decoy, key(KEELSIGN_ALG_LMS_HSS, &copy)];
        let (status, out) = call(image, &keys, KEELSIGN_POLICY_PQ_ONLY);
        assert_eq!(status, KEELSIGN_OK);
        assert_eq!(out.pq_key_index, 1);
    }

    /// TP1 / AC4: each argument error, and that the earlier check wins when several are
    /// wrong (NULL → length → policy → per key: algorithm, NULL, count, length → key set
    /// → image). `out` is never written.
    #[test]
    fn argument_errors_in_documented_order() {
        let case = case("keelsign-lms-m32-h5.bin");
        let image = policy_kat::image(case.name).unwrap();
        let lms = key(KEELSIGN_ALG_LMS_HSS, case.public_key);
        let pq = KEELSIGN_POLICY_PQ_ONLY;
        let null_key = keelsign_key_t {
            alg: KEELSIGN_ALG_LMS_HSS,
            key: ptr::null(),
            key_len: 60,
        };
        let bad_alg = key(keelsign_alg_t(9), case.public_key);
        let short = key(KEELSIGN_ALG_LMS_HSS, &case.public_key[..59]);
        let long = keelsign_key_t {
            key_len: 1953,
            ..lms
        };
        let ed_short = key(KEELSIGN_ALG_ED25519, &ED25519_TEST_KEY[..31]);
        let mut out = sentinel();

        // NULL image beats everything else.
        // SAFETY: the image pointer is NULL, which the function rejects before reading
        // anything; `out` is a live local.
        let status = unsafe {
            keelsign_verify(
                ptr::null(),
                usize::MAX,
                ptr::null(),
                1,
                keelsign_policy_t(7),
                &mut out,
            )
        };
        assert_eq!(status, KEELSIGN_ERR_NULL_POINTER);
        // NULL keys with n_keys > 0, before the length and policy checks.
        // SAFETY: `keys` is NULL with `n_keys` 1, rejected before anything is read.
        let status = unsafe {
            keelsign_verify(
                image.as_ptr(),
                usize::MAX,
                ptr::null(),
                1,
                keelsign_policy_t(7),
                &mut out,
            )
        };
        assert_eq!(status, KEELSIGN_ERR_NULL_POINTER);
        // Length before policy; nothing is read for a too-large length.
        #[cfg(target_pointer_width = "64")]
        {
            let too_large = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
            // SAFETY: the length check fails before the image or keys are read.
            let status = unsafe {
                keelsign_verify(
                    image.as_ptr(),
                    too_large,
                    ptr::null(),
                    0,
                    keelsign_policy_t(7),
                    &mut out,
                )
            };
            assert_eq!(status, KEELSIGN_ERR_IMAGE_TOO_LARGE);
            let mut d = [0xA5u8; 32];
            // SAFETY: the length check fails before anything is read; `d` is a live
            // 32-byte local.
            let status = unsafe { keelsign_digest(image.as_ptr(), too_large, d.as_mut_ptr()) };
            assert_eq!(status, KEELSIGN_ERR_IMAGE_TOO_LARGE);
            assert_eq!(d, [0xA5; 32]);
        }
        // Policy before any key.
        for policy in [0, 4, 7, u32::MAX] {
            assert_eq!(
                call(image, &[bad_alg, null_key], keelsign_policy_t(policy)).0,
                KEELSIGN_ERR_INVALID_POLICY
            );
        }
        // Per key: algorithm before NULL; keys are checked in array order.
        assert_eq!(
            call(image, &[bad_alg], pq).0,
            KEELSIGN_ERR_INVALID_ALGORITHM
        );
        assert_eq!(
            call(
                image,
                &[keelsign_key_t {
                    alg: keelsign_alg_t(0),
                    ..null_key
                }],
                pq
            )
            .0,
            KEELSIGN_ERR_INVALID_ALGORITHM
        );
        assert_eq!(
            call(image, &[null_key, bad_alg], pq).0,
            KEELSIGN_ERR_NULL_POINTER
        );
        assert_eq!(
            call(image, &[lms, bad_alg], pq).0,
            KEELSIGN_ERR_INVALID_ALGORITHM
        );
        // Count: the ninth key of a kind fails, even if it is also too short; the
        // eighth too-long one fails on its length first.
        let nine = [lms; 9];
        assert_eq!(call(image, &nine, pq).0, KEELSIGN_ERR_TOO_MANY_KEYS);
        let mut eight_then_short = [lms; 9];
        eight_then_short[8] = short;
        assert_eq!(
            call(image, &eight_then_short, pq).0,
            KEELSIGN_ERR_TOO_MANY_KEYS
        );
        let ed = key(KEELSIGN_ALG_ED25519, &ED25519_TEST_KEY);
        let mut ed_nine = [ed; 10];
        ed_nine[0] = lms;
        assert_eq!(call(image, &ed_nine, pq).0, KEELSIGN_ERR_TOO_MANY_KEYS);
        // Length: exactly 32 bytes for Ed25519, 1312 / 1952 for ML-DSA-44/65, 52 or 60
        // for LMS/HSS.
        assert_eq!(call(image, &[ed_short], pq).0, KEELSIGN_ERR_KEY_LENGTH);
        assert_eq!(call(image, &[long], pq).0, KEELSIGN_ERR_KEY_LENGTH);
        assert_eq!(call(image, &[short], pq).0, KEELSIGN_ERR_KEY_LENGTH);
        let empty = keelsign_key_t { key_len: 0, ..lms };
        assert_eq!(call(image, &[empty], pq).0, KEELSIGN_ERR_KEY_LENGTH);
        let mldsa_short = key(KEELSIGN_ALG_MLDSA44, case.public_key);
        assert_eq!(call(image, &[mldsa_short], pq).0, KEELSIGN_ERR_KEY_LENGTH);
        // Per-key checks run before the key set: a duplicate pair then a bad length.
        assert_eq!(
            call(image, &[lms, lms, short], pq).0,
            KEELSIGN_ERR_KEY_LENGTH
        );
        // Key set: duplicates (PQ, then Ed25519).
        assert_eq!(call(image, &[lms, lms], pq).0, KEELSIGN_ERR_DUPLICATE_KEY);
        assert_eq!(call(image, &[ed, ed], pq).0, KEELSIGN_ERR_DUPLICATE_KEY);
        // The image last: no keys, zero length, garbage.
        assert_eq!(call(image, &[], pq).0, KEELSIGN_ERR_KEY_NOT_TRUSTED);
        assert_eq!(
            call(&image[..0], &[lms], pq).0,
            KEELSIGN_ERR_PARSE_TRUNCATED
        );
        assert_eq!(call(&[0u8; 40], &[lms], pq).0, KEELSIGN_ERR_PARSE_BAD_MAGIC);
        // n_keys 0 with keys NULL is fine.
        // SAFETY: `image` is a live slice; `keys` is NULL with `n_keys` 0, so never read.
        let status =
            unsafe { keelsign_verify(image.as_ptr(), image.len(), ptr::null(), 0, pq, &mut out) };
        assert_eq!(status, KEELSIGN_ERR_KEY_NOT_TRUSTED);
        // keelsign_digest: either pointer NULL.
        let mut d = [0xA5u8; 32];
        // SAFETY: the image pointer is NULL and rejected before anything is read.
        let status = unsafe { keelsign_digest(ptr::null(), image.len(), d.as_mut_ptr()) };
        assert_eq!(status, KEELSIGN_ERR_NULL_POINTER);
        // SAFETY: the output pointer is NULL and rejected before anything is read.
        let status = unsafe { keelsign_digest(image.as_ptr(), image.len(), ptr::null_mut()) };
        assert_eq!(status, KEELSIGN_ERR_NULL_POINTER);
        assert_eq!(digest(&image[..0]).0, KEELSIGN_ERR_PARSE_TRUNCATED);
        assert_eq!(d, [0xA5; 32]);
        assert_eq!(out, sentinel(), "out is never written on failure");
    }

    /// AC4: run under miri (`cargo +nightly-2026-09-29 miri test -p keelsign-ffi`): the
    /// image, keys, key bytes and outputs at odd addresses, each in an allocation of
    /// exactly its size, so an out-of-bounds or misaligned access is reported; `out` NULL
    /// is accepted.
    #[test]
    fn pointer_contract_is_honoured_under_miri() {
        let case = case("keelsign-lms-m32-h5.bin");
        let image = policy_kat::image(case.name).unwrap();

        // The image at an odd address, in a buffer that ends exactly where it does.
        let mut shifted: Vec<u8> = Vec::with_capacity(image.len() + 1);
        shifted.push(0);
        shifted.extend_from_slice(image);
        let shifted = shifted.into_boxed_slice();
        let odd_image = &shifted[1..];
        assert_eq!(odd_image.len(), image.len());

        // The key bytes at an odd address, exactly sized.
        let mut key_buf: Vec<u8> = Vec::with_capacity(case.public_key.len() + 1);
        key_buf.push(0);
        key_buf.extend_from_slice(case.public_key);
        let key_buf = key_buf.into_boxed_slice();
        let odd_key = &key_buf[1..];

        // The keys array itself misaligned: one key at byte offset 1 of a byte buffer.
        let entry = key(KEELSIGN_ALG_LMS_HSS, odd_key);
        let size = core::mem::size_of::<keelsign_key_t>();
        let mut keys_buf: Box<[u8]> = std::vec![0u8; size + 1].into_boxed_slice();
        // SAFETY: `keys_buf` has `size + 1` bytes, so `size` bytes from offset 1 are in
        // bounds; `write_unaligned` accepts any alignment.
        unsafe {
            keys_buf
                .as_mut_ptr()
                .add(1)
                .cast::<keelsign_key_t>()
                .write_unaligned(entry);
        }
        // SAFETY: offset 1 of a `size + 1`-byte buffer, as written above.
        let keys_ptr = unsafe { keys_buf.as_ptr().add(1).cast::<keelsign_key_t>() };

        // `out` misaligned the same way.
        let out_size = core::mem::size_of::<keelsign_result_t>();
        let mut out_buf: Box<[u8]> = std::vec![0u8; out_size + 1].into_boxed_slice();
        // SAFETY: offset 1 of an `out_size + 1`-byte buffer.
        let out_ptr = unsafe { out_buf.as_mut_ptr().add(1).cast::<keelsign_result_t>() };

        // SAFETY: every pointer refers to a live, exactly sized buffer of the length
        // passed (`odd_image`, one key in `keys_buf`, `odd_key`, `out_buf`); alignment is
        // deliberately 1, which the contract allows.
        let status = unsafe {
            keelsign_verify(
                odd_image.as_ptr(),
                odd_image.len(),
                keys_ptr,
                1,
                KEELSIGN_POLICY_PQ_ONLY,
                out_ptr,
            )
        };
        assert_eq!(status, KEELSIGN_OK);
        // SAFETY: `out_ptr` was just written as a whole `keelsign_result_t`.
        let out = unsafe { out_ptr.read_unaligned() };
        assert_eq!(out.pq_key_index, 0);
        assert_eq!(out.ed25519_key_index, KEELSIGN_NO_KEY);
        assert_eq!(out.image_len as usize, image.len());

        // `out` NULL: accepted. Outside miri on a valid image; under miri on one whose
        // body is tampered, which is still read and hashed in full (a second LMS/HSS verify
        // would take minutes there).
        let mut tampered: Vec<u8> = odd_image.to_vec();
        tampered[600] ^= 1;
        let (null_out_image, expected) = if cfg!(miri) {
            (&tampered[..], KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH)
        } else {
            (odd_image, KEELSIGN_OK)
        };
        // SAFETY: as above (`tampered` is a live slice of the length passed), with `out`
        // NULL, which the contract allows.
        let status = unsafe {
            keelsign_verify(
                null_out_image.as_ptr(),
                null_out_image.len(),
                keys_ptr,
                1,
                KEELSIGN_POLICY_PQ_ONLY,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, expected);

        // The digest written to an odd address, into exactly 32 bytes.
        let mut digest_buf: Box<[u8]> = std::vec![0u8; 33].into_boxed_slice();
        // SAFETY: `odd_image` is live; offset 1 of a 33-byte buffer leaves exactly 32
        // writable bytes.
        let status = unsafe {
            keelsign_digest(
                odd_image.as_ptr(),
                odd_image.len(),
                digest_buf.as_mut_ptr().add(1),
            )
        };
        assert_eq!(status, KEELSIGN_OK);
        assert_eq!(digest_buf[1..], out.digest);

        // A truncated image: every read stays inside the shorter, exactly sized buffer.
        let truncated: Box<[u8]> = image[..image.len() - 1].to_vec().into_boxed_slice();
        let keys = [key(KEELSIGN_ALG_LMS_HSS, odd_key)];
        let (status, _) = call(&truncated, &keys, KEELSIGN_POLICY_PQ_ONLY);
        assert_ne!(status, KEELSIGN_OK);
        assert_ne!(digest(&truncated[..32]).0, KEELSIGN_OK);
    }

    /// AC4: on every failure path `*out` and `out_digest` keep their old bytes.
    #[test]
    fn out_is_untouched_on_failure() {
        let case = case("keelsign-lms-m32-h5.bin");
        let image = policy_kat::image(case.name).unwrap();
        let lms = key(KEELSIGN_ALG_LMS_HSS, case.public_key);
        let mut tampered = image.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut body = image.to_vec();
        body[600] ^= 1;
        let one = [lms];
        let two = [lms, lms];
        let zero: [keelsign_key_t; 0] = [];
        let zeros = [0u8; 64];
        // Under miri the signature-arithmetic paths (a flipped signature byte, the
        // successful verify) are skipped: each LMS/HSS verify takes minutes there.
        let mut failures: Vec<(&[u8], &[keelsign_key_t], keelsign_policy_t)> = std::vec![
            (&body, &one, KEELSIGN_POLICY_PQ_ONLY),
            (image, &zero, KEELSIGN_POLICY_PQ_ONLY),
            (image, &two, KEELSIGN_POLICY_PQ_ONLY),
            (image, &one, keelsign_policy_t(0)),
            (&image[..10], &one, KEELSIGN_POLICY_PQ_ONLY),
            (&zeros, &one, KEELSIGN_POLICY_PQ_ONLY),
        ];
        if !cfg!(miri) {
            failures.push((&tampered, &one, KEELSIGN_POLICY_PQ_ONLY));
        }
        for (i, (img, keys, policy)) in failures.iter().enumerate() {
            let (status, out) = call(img, keys, *policy);
            assert_ne!(status, KEELSIGN_OK, "failure {i}");
            assert_eq!(out, sentinel(), "failure {i}: out written");
        }
        for img in [&image[..10], &[0u8; 64][..], &[][..]] {
            let (status, out) = digest(img);
            assert_ne!(status, KEELSIGN_OK);
            assert_eq!(out, [0xA5; 32]);
        }
        // And the success path does write it.
        if !cfg!(miri) {
            let (status, out) = call(image, &[lms], KEELSIGN_POLICY_PQ_ONLY);
            assert_eq!(status, KEELSIGN_OK);
            assert_ne!(out, sentinel());
        }
    }
}
