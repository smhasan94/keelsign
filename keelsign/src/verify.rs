//! `keelsign verify`: check an MCUboot image's signatures against trusted public keys
//! under a device policy (see `docs/verify.md`).
//!
//! The image is checked by [`verify_bytes`], the one call to
//! [`keelsign_verify::verify_with`] in the CLI: the same image rules, digest and signature
//! checks the device runs, with the policy and key set given on the command line. The
//! public keys are `SubjectPublicKeyInfo` files ([`PublicKey`]).

use crate::cli::PolicyArg;
use crate::error::Error;
use crate::image_file;
use crate::keyfile;
use crate::keys::{PublicKey, hex};
use keelsign_verify::image::ImageVersion;
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, DefaultBackend, Ed25519Key, KeySetError, Policy, TrustedKey,
    TrustedKeys, VerifiedImage,
};
use std::path::{Path, PathBuf};

/// Most `--pub` keys of each kind (post-quantum, Ed25519): the key set's capacity.
pub const MAX_KEYS_PER_KIND: usize = 8;

/// What `verify` needs: the paths and switches of the command line.
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    /// The image to verify.
    pub image: PathBuf,
    /// The trusted public key files (`--pub`), in order.
    pub pubs: Vec<PathBuf>,
    /// The policy (`--policy`), or `None` to infer it from the keys.
    pub policy: Option<PolicyArg>,
    /// Verify with [`DefaultBackend::cnsa_2_0`] (`--cnsa-2.0`).
    pub cnsa_2_0: bool,
}

/// The CLI name of a policy: `classical`, `pq` or `hybrid`.
pub fn policy_name(policy: Policy) -> &'static str {
    match policy {
        Policy::ClassicalOnly => "classical",
        Policy::PqOnly => "pq",
        Policy::Hybrid => "hybrid",
        // `Policy` is #[non_exhaustive]; the CLI only ever builds the three above.
        _ => "unknown",
    }
}

/// The CLI name of a post-quantum algorithm.
fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::MlDsa44 => "ml-dsa-44",
        Algorithm::MlDsa65 => "ml-dsa-65",
        Algorithm::LmsHss => "lms-hss",
        // `Algorithm` is #[non_exhaustive]; the CLI only reads keys of the three above.
        _ => "unknown",
    }
}

/// How the CLI reports a [`keelsign_verify::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitClass {
    /// The image is not one keelsign reads (exit 7).
    Malformed,
    /// The image is well formed but not verified under the policy (exit 9).
    NotVerified,
    /// The CLI used the verifier wrongly (exit 1).
    Internal,
}

/// The exit class of a verifier error: [`ExitClass::Malformed`] for an image that does
/// not parse, [`ExitClass::Internal`] for a misuse of the verifier, and
/// [`ExitClass::NotVerified`] for everything else (signatures, keys, policy, image rules).
pub fn exit_class(error: &keelsign_verify::Error) -> ExitClass {
    use keelsign_verify::Error as E;
    match error {
        E::Parse(_) | E::Read(_) | E::TlvAreaTooLarge => ExitClass::Malformed,
        E::ChunkBufferEmpty => ExitClass::Internal,
        E::MissingKeyId
        | E::InvalidKeyId
        | E::MultipleKeyIds
        | E::MissingPqSignature
        | E::MultiplePqSignatures
        | E::KeyNotTrusted
        | E::KeyAlgorithmMismatch
        | E::UnsupportedAlgorithm(_)
        | E::UnsupportedParameterSet
        | E::MalformedSignature
        | E::SignatureInvalid
        // The next two arms: unreachable for keys the CLI loaded since SHA-302:
        // `InvalidPublicKey` and `Ed25519(Ed25519Error::InvalidPublicKey)` are refused at
        // load (exit 5); the other `Ed25519` variants are reachable. Kept at 9 because a
        // verifier error is never a reason to accept.
        | E::InvalidPublicKey
        | E::Ed25519(_)
        | E::Image(_) => ExitClass::NotVerified,
        // `keelsign_verify::Error` is #[non_exhaustive]: a variant added later is a reason
        // not to accept the image, never a reason to accept it.
        _ => ExitClass::NotVerified,
    }
}

/// Verify `bytes` under `policy` against `keys`, as the device does: the one call to
/// [`keelsign_verify::verify_with`], with [`DefaultBackend::cnsa_2_0`] when `cnsa_2_0`
/// and [`DefaultBackend::new`] otherwise. Bytes after the TLV area (padding, a slot
/// trailer) are not read.
pub fn verify_bytes<'k, const N: usize, const E: usize>(
    bytes: &[u8],
    keys: &TrustedKeys<'k, N, E>,
    policy: Policy,
    cnsa_2_0: bool,
) -> Result<VerifiedImage<'k>, keelsign_verify::Error> {
    let backend = if cnsa_2_0 {
        DefaultBackend::cnsa_2_0()
    } else {
        DefaultBackend::new()
    };
    let mut reader: &[u8] = bytes;
    let mut tlv_buf = vec![0u8; bytes.len()];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    keelsign_verify::verify_with(
        &backend,
        &mut reader,
        keys,
        policy,
        &mut tlv_buf,
        &mut chunk,
    )
}

/// Read every `--pub` file, in order: an unreadable file is an I/O error (exit 1), a file
/// that is not a supported public key a key-file error (exit 5). Keys are decoded when
/// loaded (Ed25519 point, LMS parameters), whatever the policy. More than
/// [`MAX_KEYS_PER_KIND`] keys of a kind, or the same key twice, is a usage error (exit 2).
pub fn load_public_keys(paths: &[PathBuf]) -> Result<Vec<PublicKey>, Error> {
    let mut keys: Vec<(&Path, PublicKey)> = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = keyfile::read_key_file(path)?;
        let key = PublicKey::from_bytes(&bytes).map_err(|e| Error::key_file(path, e))?;
        if let Some((first, _)) = keys.iter().find(|(_, k)| k.raw() == key.raw()) {
            return Err(Error::Usage(format!(
                "--pub {} and --pub {} are the same {} key",
                first.display(),
                path.display(),
                key.algorithm_name()
            )));
        }
        keys.push((path, key));
    }
    let ed25519 = keys
        .iter()
        .filter(|(_, k)| k.ed25519_key().is_some())
        .count();
    let pq = keys.len() - ed25519;
    for (count, kind) in [(pq, "post-quantum"), (ed25519, "Ed25519")] {
        if count > MAX_KEYS_PER_KIND {
            return Err(Error::Usage(format!(
                "{count} {kind} --pub keys given; at most {MAX_KEYS_PER_KIND} are accepted"
            )));
        }
    }
    Ok(keys.into_iter().map(|(_, k)| k).collect())
}

/// The policy to verify under: `requested`, or, when it is `None`, the one the keys
/// imply (post-quantum keys only: `pq`; Ed25519 keys only: `classical`; both: `hybrid`).
/// Returns the policy and whether it was inferred.
pub fn infer_policy(
    requested: Option<PolicyArg>,
    keys: &[PublicKey],
) -> Result<(Policy, bool), Error> {
    if let Some(policy) = requested {
        return Ok((policy.into(), false));
    }
    let has_pq = keys.iter().any(|k| k.trusted_key().is_some());
    let has_ed25519 = keys.iter().any(|k| k.ed25519_key().is_some());
    match (has_pq, has_ed25519) {
        (true, true) => Ok((Policy::Hybrid, true)),
        (true, false) => Ok((Policy::PqOnly, true)),
        (false, true) => Ok((Policy::ClassicalOnly, true)),
        (false, false) => Err(Error::Usage(
            "give at least one trusted public key with --pub".into(),
        )),
    }
}

/// Fail with a usage error (exit 2) if `policy` needs a kind of key no `--pub` gives.
pub fn check_policy_keys(policy: Policy, keys: &[PublicKey]) -> Result<(), Error> {
    let name = policy_name(policy);
    if policy.requires_pq() && !keys.iter().any(|k| k.trusted_key().is_some()) {
        return Err(Error::Usage(format!(
            "--policy {name} needs a post-quantum key (ML-DSA-44, ML-DSA-65 or HSS/LMS) \
             given with --pub"
        )));
    }
    if policy.requires_ed25519() && !keys.iter().any(|k| k.ed25519_key().is_some()) {
        return Err(Error::Usage(format!(
            "--policy {name} needs an Ed25519 key given with --pub"
        )));
    }
    Ok(())
}

fn key_set_error(error: KeySetError) -> Error {
    match error {
        KeySetError::Capacity => Error::Usage(format!(
            "too many --pub keys; at most {MAX_KEYS_PER_KIND} of each kind are accepted"
        )),
        KeySetError::DuplicateKeyId => Error::Usage("two --pub keys are the same key".into()),
        other => Error::Internal(format!("could not build the key set: {other}")),
    }
}

/// What `verify` found, for its report on standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The image file.
    pub image: PathBuf,
    /// The policy it was verified under.
    pub policy: Policy,
    /// Whether the policy was inferred from the keys (no `--policy`).
    pub inferred: bool,
    /// The header's version.
    pub version: ImageVersion,
    /// The protected `SEC_CNT` value, if any.
    pub security_counter: Option<u32>,
    /// The image digest `M`.
    pub digest: [u8; 32],
    /// The algorithm and key ID of the post-quantum key that verified the image, when the
    /// policy checks the post-quantum half.
    pub pq_key: Option<(&'static str, [u8; 16])>,
    /// The KEYHASH of the Ed25519 key that verified the image, when the policy checks the
    /// Ed25519 half.
    pub ed25519_keyhash: Option<[u8; 32]>,
    /// Where the image ends (header, body and TLV areas).
    pub image_len: usize,
    /// The length of the file.
    pub file_len: usize,
}

impl VerifyReport {
    fn new(image: &Path, verified: &VerifiedImage<'_>, inferred: bool, file_len: usize) -> Self {
        Self {
            image: image.to_path_buf(),
            policy: verified.policy,
            inferred,
            version: verified.version,
            security_counter: verified.security_counter,
            digest: verified.digest,
            pq_key: verified.pq_key.map(|k: TrustedKey<'_>| {
                (
                    algorithm_name(k.algorithm),
                    keelsign_verify::key_id_of(k.public_key),
                )
            }),
            ed25519_keyhash: verified.ed25519_key.map(|k: Ed25519Key<'_>| k.keyhash()),
            image_len: usize::try_from(verified.image_len).unwrap_or(usize::MAX),
            file_len,
        }
    }

    /// The report lines, without a trailing newline: `verified:`, `policy:`, `version:`,
    /// `security counter:`, `image digest:`, then `pq key:` and `ed25519 key:` for the
    /// halves checked, and `image:` when bytes follow the TLV area.
    pub fn lines(&self) -> Vec<String> {
        let v = &self.version;
        let mut lines = vec![
            format!("verified: {}", self.image.display()),
            format!(
                "policy: {}{}",
                policy_name(self.policy),
                if self.inferred {
                    " (inferred from the keys given)"
                } else {
                    ""
                }
            ),
            format!(
                "version: {}.{}.{}+{}",
                v.major, v.minor, v.revision, v.build_num
            ),
            match self.security_counter {
                Some(counter) => format!("security counter: {counter}"),
                None => "security counter: none".into(),
            },
            format!("image digest: {}", hex(&self.digest)),
        ];
        if let Some((algorithm, key_id)) = &self.pq_key {
            lines.push(format!("pq key: {algorithm} {}", hex(key_id)));
        }
        if let Some(keyhash) = &self.ed25519_keyhash {
            lines.push(format!("ed25519 key: {}", hex(keyhash)));
        }
        let trailing = self.file_len.saturating_sub(self.image_len);
        if trailing > 0 {
            lines.push(format!(
                "image: {} bytes ({trailing} trailing bytes ignored)",
                self.file_len
            ));
        }
        lines
    }
}

/// Run `keelsign verify`: read the image (exit 7 if it is not an MCUboot image) and the
/// `--pub` keys, choose the policy and verify. A verifier error is reported by its
/// [`exit_class`]: 7, 9 ([`Error::NotVerified`]) or 1.
pub fn run(request: &VerifyRequest) -> Result<VerifyReport, Error> {
    let bytes = image_file::read_image(&request.image)?;
    // Reject a file that is not an MCUboot image before reading the keys.
    image_file::parse(&request.image, &bytes)?;
    let public_keys = load_public_keys(&request.pubs)?;
    let pq: Vec<TrustedKey<'_>> = public_keys
        .iter()
        .filter_map(PublicKey::trusted_key)
        .collect();
    let ed25519: Vec<Ed25519Key<'_>> = public_keys
        .iter()
        .filter_map(PublicKey::ed25519_key)
        .collect();
    let keys = TrustedKeys::<MAX_KEYS_PER_KIND, MAX_KEYS_PER_KIND>::with_ed25519(&pq, &ed25519)
        .map_err(key_set_error)?;
    let (policy, inferred) = infer_policy(request.policy, &public_keys)?;
    check_policy_keys(policy, &public_keys)?;
    match verify_bytes(&bytes, &keys, policy, request.cnsa_2_0) {
        Ok(verified) => Ok(VerifyReport::new(
            &request.image,
            &verified,
            inferred,
            bytes.len(),
        )),
        Err(source) => Err(match exit_class(&source) {
            ExitClass::Malformed => Error::Image {
                path: request.image.clone(),
                reason: format!("not an MCUboot image keelsign reads: {source}"),
            },
            ExitClass::NotVerified => Error::NotVerified {
                path: request.image.clone(),
                policy,
                source,
            },
            ExitClass::Internal => Error::Internal(format!("could not verify the image: {source}")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keelsign_verify::image::ParseError;
    use keelsign_verify::{Ed25519Error, ImageError, ReadError};

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/images")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn ed25519_test_key() -> PublicKey {
        PublicKey::from_bytes(&fixture("keys/ed25519-test-key.spki.der")).expect("SPKI")
    }

    fn mldsa_key() -> PublicKey {
        PublicKey::MlDsa44(vec![7; 1312])
    }

    #[test]
    fn every_verify_error_variant_has_an_exit_class() {
        use keelsign_verify::Error as E;
        let cases = [
            (E::MissingKeyId, ExitClass::NotVerified),
            (E::InvalidKeyId, ExitClass::NotVerified),
            (E::MultipleKeyIds, ExitClass::NotVerified),
            (E::MissingPqSignature, ExitClass::NotVerified),
            (E::MultiplePqSignatures, ExitClass::NotVerified),
            (E::KeyNotTrusted, ExitClass::NotVerified),
            (E::KeyAlgorithmMismatch, ExitClass::NotVerified),
            (
                E::UnsupportedAlgorithm(Algorithm::MlDsa44),
                ExitClass::NotVerified,
            ),
            (E::UnsupportedParameterSet, ExitClass::NotVerified),
            (E::MalformedSignature, ExitClass::NotVerified),
            (E::InvalidPublicKey, ExitClass::NotVerified),
            (E::SignatureInvalid, ExitClass::NotVerified),
            (E::Parse(ParseError::BadMagic), ExitClass::Malformed),
            (E::Parse(ParseError::Truncated), ExitClass::Malformed),
            (E::Read(ReadError::Other), ExitClass::Malformed),
            (E::TlvAreaTooLarge, ExitClass::Malformed),
            (E::ChunkBufferEmpty, ExitClass::Internal),
            (
                E::Ed25519(Ed25519Error::SignatureInvalid),
                ExitClass::NotVerified,
            ),
            (E::Ed25519(Ed25519Error::NotEnabled), ExitClass::NotVerified),
            (E::Image(ImageError::DigestMismatch), ExitClass::NotVerified),
        ];
        for (error, class) in cases {
            assert_eq!(exit_class(&error), class, "{error:?}");
            let exit = match class {
                ExitClass::Malformed => 7,
                ExitClass::NotVerified => 9,
                ExitClass::Internal => 1,
            };
            let cli = match class {
                ExitClass::Malformed => Error::Image {
                    path: "a.bin".into(),
                    reason: error.to_string(),
                },
                ExitClass::NotVerified => Error::NotVerified {
                    path: "a.bin".into(),
                    policy: Policy::PqOnly,
                    source: error,
                },
                ExitClass::Internal => Error::Internal(error.to_string()),
            };
            assert_eq!(cli.exit_code(), exit, "{error:?}");
        }
    }

    #[test]
    fn policy_inference_table() {
        let pq = mldsa_key();
        let ed = ed25519_test_key();
        let lms = PublicKey::LmsHss(vec![0; 60]);
        let cases: [(&[PublicKey], Option<PolicyArg>, Policy, bool); 7] = [
            (std::slice::from_ref(&pq), None, Policy::PqOnly, true),
            (std::slice::from_ref(&lms), None, Policy::PqOnly, true),
            (std::slice::from_ref(&ed), None, Policy::ClassicalOnly, true),
            (&[pq.clone(), ed.clone()], None, Policy::Hybrid, true),
            (
                &[pq.clone(), ed.clone()],
                Some(PolicyArg::Pq),
                Policy::PqOnly,
                false,
            ),
            (
                &[pq.clone(), ed.clone()],
                Some(PolicyArg::Classical),
                Policy::ClassicalOnly,
                false,
            ),
            (
                std::slice::from_ref(&pq),
                Some(PolicyArg::Hybrid),
                Policy::Hybrid,
                false,
            ),
        ];
        for (keys, requested, policy, inferred) in cases {
            assert_eq!(
                infer_policy(requested, keys).expect("policy"),
                (policy, inferred),
                "{requested:?}"
            );
        }
        // An inferred policy always has its keys; a requested one may not.
        assert!(check_policy_keys(Policy::PqOnly, std::slice::from_ref(&pq)).is_ok());
        assert!(check_policy_keys(Policy::Hybrid, &[pq.clone(), ed.clone()]).is_ok());
        let err = check_policy_keys(Policy::Hybrid, std::slice::from_ref(&pq)).expect_err("ed");
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.to_string()
                .contains("--policy hybrid needs an Ed25519 key")
        );
        let err = check_policy_keys(Policy::PqOnly, std::slice::from_ref(&ed)).expect_err("pq");
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.to_string()
                .contains("--policy pq needs a post-quantum key")
        );
        let err = check_policy_keys(Policy::ClassicalOnly, &[pq]).expect_err("ed");
        assert!(
            err.to_string()
                .contains("--policy classical needs an Ed25519 key")
        );
        assert_eq!(infer_policy(None, &[]).expect_err("none").exit_code(), 2);
        for (policy, name) in [
            (Policy::ClassicalOnly, "classical"),
            (Policy::PqOnly, "pq"),
            (Policy::Hybrid, "hybrid"),
        ] {
            assert_eq!(policy_name(policy), name);
        }
    }

    #[test]
    fn report_lines() {
        let mut report = VerifyReport {
            image: "app.bin".into(),
            policy: Policy::Hybrid,
            inferred: true,
            version: ImageVersion {
                major: 1,
                minor: 2,
                revision: 3,
                build_num: 4,
            },
            security_counter: Some(7),
            digest: [0xab; 32],
            pq_key: Some(("ml-dsa-65", [0xcd; 16])),
            ed25519_keyhash: Some([0xef; 32]),
            image_len: 100,
            file_len: 100,
        };
        assert_eq!(
            report.lines(),
            [
                "verified: app.bin".to_owned(),
                "policy: hybrid (inferred from the keys given)".to_owned(),
                "version: 1.2.3+4".to_owned(),
                "security counter: 7".to_owned(),
                format!("image digest: {}", "ab".repeat(32)),
                format!("pq key: ml-dsa-65 {}", "cd".repeat(16)),
                format!("ed25519 key: {}", "ef".repeat(32)),
            ]
        );
        report.inferred = false;
        report.policy = Policy::ClassicalOnly;
        report.security_counter = None;
        report.pq_key = None;
        report.file_len = 8192;
        let lines = report.lines();
        assert_eq!(lines[1], "policy: classical");
        assert_eq!(lines[3], "security counter: none");
        assert!(lines[5].starts_with("ed25519 key: "), "{lines:?}");
        assert_eq!(lines[6], "image: 8192 bytes (8092 trailing bytes ignored)");
        assert_eq!(lines.len(), 7);
    }

    #[test]
    fn verify_bytes_is_keelsign_verify_with() {
        // Source level: this module (outside its tests) calls the verifier exactly once,
        // through verify_with.
        let source = include_str!("verify.rs")
            .split(concat!("#[cfg(", "test)]"))
            .next()
            .expect("source");
        let with = concat!("keelsign_verify::verify_with", "(");
        let plain = concat!("keelsign_verify::verify", "(");
        assert_eq!(source.matches(with).count(), 1, "one verify_with call");
        assert_eq!(source.matches(plain).count(), 0, "no verify call");

        // Behaviour: the same verdict as keelsign_verify::verify on the fixtures.
        let ed = ed25519_test_key();
        let ed_keys = [ed.ed25519_key().expect("ed25519")];
        let keys = TrustedKeys::<1, 1>::with_ed25519(&[], &ed_keys).expect("keys");
        for name in [
            "mcuboot-ed25519.bin",
            "mcuboot-ed25519-padded.bin",
            "mcuboot-rsa2048.bin",
        ] {
            let bytes = fixture(name);
            for &policy in Policy::ALL {
                let mut reader: &[u8] = &bytes;
                let mut tlv_buf = vec![0u8; bytes.len()];
                let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
                let expected =
                    keelsign_verify::verify(&mut reader, &keys, policy, &mut tlv_buf, &mut chunk);
                assert_eq!(
                    verify_bytes(&bytes, &keys, policy, false),
                    expected,
                    "{name} {policy:?}"
                );
            }
        }
    }
}
