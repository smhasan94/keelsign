//! `keelsign sign`: add a post-quantum signature (and optionally an Ed25519 pair) to an
//! MCUboot image (see `docs/signing.md`).
//!
//! The bytes the image digest `M` covers (header, body, protected TLV area) are never
//! changed: the new TLVs are appended to the unprotected area, after every MCUboot TLV,
//! in the order of docs/image-format.md (`KEYHASH`, `ED25519`, key ID, PQ signature).
//! ML-DSA signing is hedged (FIPS 204 randomized, with the operating system's
//! random-number generator), pure, with the keelsign context. LMS/HSS signing
//! ([`crate::lms_sign`]) first reserves a leaf in the key's state file
//! ([`crate::lms_state::reserve`]): after the image is parsed, the keys are loaded and
//! `M` is computed, before any signature is computed. Every image is verified with
//! `keelsign_verify::verify` before it is written.

use crate::error::{Error, KeyFileError};
use crate::image_file::{self, Precheck, UnprotectedArea};
use crate::keyfile;
use crate::keys::{KeyAlgorithm, PrivateKey};
use crate::lms_state::Reservation;
use keelsign_verify::image::Image;
use keelsign_verify::image::{IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH};
use keelsign_verify::tlv::{MLDSA_CONTEXT, TLV_KEELSIGN_KEY_ID};
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, Ed25519Key, Policy, TrustedKey, TrustedKeys, key_id_of,
    keyhash_of,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// What `sign` needs: the paths and switches of the command line.
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// The input image.
    pub input: PathBuf,
    /// The signed image to write.
    pub output: PathBuf,
    /// The ML-DSA or LMS/HSS private key file (`--key`).
    pub key: PathBuf,
    /// The Ed25519 private key file (`--hybrid-key`), for a hybrid image.
    pub hybrid_key: Option<PathBuf>,
    /// Replace existing keelsign TLVs (and, with `hybrid_key`, an Ed25519 pair).
    pub replace: bool,
    /// Replace `output` if it exists.
    pub force: bool,
}

/// What `sign` did, for its report on standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignReport {
    /// The post-quantum algorithm.
    pub algorithm: KeyAlgorithm,
    /// The key ID written to the image.
    pub key_id: [u8; 16],
    /// The KEYHASH of the Ed25519 key, for a hybrid image.
    pub keyhash: Option<[u8; 32]>,
    /// The image digest `M` the signatures are over.
    pub digest: [u8; 32],
    /// Length of the signed image.
    pub output_len: usize,
    /// Length of the input image.
    pub input_len: usize,
    /// The leaf an LMS/HSS signature used.
    pub leaf: Option<LeafReport>,
}

/// The leaf an LMS/HSS signature used, for `sign`'s report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafReport {
    /// The leaf (global over both HSS levels).
    pub index: u64,
    /// The number of leaves of the key.
    pub total: u64,
    /// The state file, which already names the next leaf.
    pub state_path: PathBuf,
}

impl SignReport {
    /// The report lines (`algorithm:`, `key id:`, optional `keyhash:`, `image digest:`,
    /// for LMS/HSS `leaf:` and `state:`, then `signed:`), without a trailing newline.
    pub fn lines(&self, output: &Path) -> Vec<String> {
        let mut lines = vec![
            format!("algorithm: {}", self.algorithm),
            format!("key id: {}", crate::keys::hex(&self.key_id)),
        ];
        if let Some(keyhash) = &self.keyhash {
            lines.push(format!("keyhash: {}", crate::keys::hex(keyhash)));
        }
        lines.push(format!("image digest: {}", crate::keys::hex(&self.digest)));
        if let Some(leaf) = &self.leaf {
            lines.push(format!(
                "leaf: {} of {} ({} left)",
                leaf.index,
                leaf.total,
                leaf.total - leaf.index - 1
            ));
            lines.push(format!(
                "state: {} (next leaf {})",
                leaf.state_path.display(),
                leaf.index + 1
            ));
        }
        let added = self.output_len as i128 - self.input_len as i128;
        lines.push(format!(
            "signed: {} ({} bytes, {added:+} bytes of TLVs)",
            output.display(),
            self.output_len
        ));
        lines
    }
}

/// A loaded key and whether the shared passphrase decrypted it.
fn load_key(path: &Path, passphrase: Option<&[u8]>) -> Result<(PrivateKey, bool), Error> {
    let bytes = keyfile::read_key_file(path)?;
    match PrivateKey::from_bytes(&bytes, passphrase) {
        Ok(key) => Ok((key, passphrase.is_some())),
        // The passphrase is shared by --key and --hybrid-key: it belongs to the other one.
        Err(KeyFileError::PassphraseUnexpected) if passphrase.is_some() => {
            PrivateKey::from_bytes(&bytes, None)
                .map(|key| (key, false))
                .map_err(|e| Error::key_file(path, e))
        }
        Err(e) => Err(Error::key_file(path, e)),
    }
}

/// The ML-DSA or LMS/HSS key of `--key` and the Ed25519 key of `--hybrid-key`, with the
/// shared passphrase applied to whichever is encrypted.
pub fn load_keys(
    key: &Path,
    hybrid_key: Option<&Path>,
    passphrase: Option<&[u8]>,
) -> Result<(PrivateKey, Option<PrivateKey>), Error> {
    let (pq, pq_used) = load_key(key, passphrase)?;
    if pq.algorithm() == KeyAlgorithm::Ed25519 {
        return Err(Error::WrongKeyKind {
            path: key.to_path_buf(),
            option: "--key",
            found: pq.algorithm(),
            expected: "an ML-DSA-44, ML-DSA-65 or LMS/HSS key",
        });
    }
    let (ed, ed_used) = match hybrid_key {
        None => (None, false),
        Some(path) => {
            let (ed, used) = load_key(path, passphrase)?;
            if ed.algorithm() != KeyAlgorithm::Ed25519 {
                return Err(Error::WrongKeyKind {
                    path: path.to_path_buf(),
                    option: "--hybrid-key",
                    found: ed.algorithm(),
                    expected: "an Ed25519 key",
                });
            }
            (Some(ed), used)
        }
    };
    if passphrase.is_some() && !pq_used && !ed_used {
        return Err(Error::key_file(key, KeyFileError::PassphraseUnexpected));
    }
    Ok((pq, ed))
}

/// The post-quantum algorithm (and so the TLV type) of an ML-DSA or LMS/HSS key.
fn pq_algorithm(key: &PrivateKey) -> Result<Algorithm, Error> {
    match key.algorithm() {
        KeyAlgorithm::MlDsa44 => Ok(Algorithm::MlDsa44),
        KeyAlgorithm::MlDsa65 => Ok(Algorithm::MlDsa65),
        KeyAlgorithm::LmsHss => Ok(Algorithm::LmsHss),
        KeyAlgorithm::Ed25519 => Err(Error::Internal("not a post-quantum key".into())),
    }
}

/// A hedged (randomized) pure ML-DSA signature over `m` with [`MLDSA_CONTEXT`].
fn sign_ml_dsa(key: &PrivateKey, m: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let rng_error = |e: ml_dsa::Error| Error::Rng(format!("ML-DSA signing failed: {e}"));
    let mut rng = getrandom::SysRng;
    match key {
        PrivateKey::MlDsa44(k) => Ok(k
            .expanded_key()
            .sign_randomized(m, MLDSA_CONTEXT, &mut rng)
            .map_err(rng_error)?
            .encode()
            .to_vec()),
        PrivateKey::MlDsa65(k) => Ok(k
            .expanded_key()
            .sign_randomized(m, MLDSA_CONTEXT, &mut rng)
            .map_err(rng_error)?
            .encode()
            .to_vec()),
        PrivateKey::Ed25519(_) | PrivateKey::LmsHss(_) => {
            Err(Error::Internal("not an ML-DSA key".into()))
        }
    }
}

/// The KEYHASH of the Ed25519 key and its RFC 8032 signature over `m`.
fn sign_ed25519(key: &PrivateKey, m: &[u8; 32]) -> Result<([u8; 32], Vec<u8>), Error> {
    use ed25519_dalek::Signer as _;
    match key {
        PrivateKey::Ed25519(k) => {
            let public = k.verifying_key().to_bytes();
            Ok((keyhash_of(&public), k.sign(m).to_bytes().to_vec()))
        }
        _ => Err(Error::Internal("not an Ed25519 key".into())),
    }
}

/// The error for an image with `trailing` bytes after its TLV area.
fn trailing_error(input: &Path, trailing: usize) -> Error {
    Error::Image {
        path: input.to_path_buf(),
        reason: format!(
            "{trailing} bytes follow the TLV area (padding or a slot trailer); sign before \
             padding; padded images are a follow-up"
        ),
    }
}

/// The post-quantum signature over `m`: hedged ML-DSA, or LMS/HSS with the leaf of
/// `reservation` (which an LMS/HSS key needs).
fn sign_pq(
    pq: &PrivateKey,
    m: &[u8; 32],
    reservation: Option<&Reservation>,
) -> Result<Vec<u8>, Error> {
    match (pq, reservation) {
        (PrivateKey::LmsHss(key), Some(r)) => {
            // The leaf is already reserved: say that it is spent, so nobody tries to
            // "retry" it by editing the state file.
            let spent = spent_leaf_message(r.leaf, r.leaves, &r.state_path);
            key.sign(r.leaf, m, &r.caches, None).map_err(|e| match e {
                crate::lms_sign::LmsError::Cache(reason) => Error::LmsState {
                    path: r.state_path.clone(),
                    reason: crate::error::LmsStateError::Corrupt(format!("{reason}; {spent}")),
                },
                other => Error::Internal(format!("LMS/HSS signing failed: {other}; {spent}")),
            })
        }
        (PrivateKey::LmsHss(_), None) => Err(Error::Internal(
            "an LMS/HSS signature needs a reserved leaf".into(),
        )),
        (other, _) => sign_ml_dsa(other, m),
    }
}

/// What a signing failure after the reservation adds: the reserved leaf is spent, and
/// what the next `sign` does (the next leaf, or nothing if that was the last one).
fn spent_leaf_message(leaf: u64, leaves: u64, state_path: &Path) -> String {
    let next = if leaf.saturating_add(1) >= leaves {
        format!("it was the last of the key's {leaves} leaves, so the key is now exhausted")
    } else {
        format!("the next sign uses leaf {}", leaf + 1)
    };
    format!(
        "leaf {leaf} is reserved in {} and is now spent (it is never reused; {next})",
        state_path.display()
    )
}

/// An image ready to sign: its existing keelsign TLVs (and, for a hybrid image, Ed25519
/// pairs) stripped, and the digest `M` the signatures will cover.
#[derive(Debug)]
pub struct Prepared<'a> {
    image: Image<'a>,
    area: UnprotectedArea,
    /// The image digest `M`.
    pub m: [u8; 32],
}

fn too_large(input: &Path, len: usize) -> Error {
    Error::Image {
        path: input.to_path_buf(),
        reason: format!(
            "the unprotected TLV area would be {len} bytes, over the 65,535 bytes \
             `it_tlv_tot` can describe"
        ),
    }
}

/// Parse the image `bytes` (read from `input`, for messages), apply `--replace` (and,
/// with `hybrid`, the Ed25519 rules), and compute `M` over the image as it will be
/// signed. Nothing is signed yet.
pub fn prepare_image<'a>(
    input: &Path,
    bytes: &'a [u8],
    hybrid: bool,
    replace: bool,
) -> Result<Prepared<'a>, Error> {
    let rejected = |reason: String| Error::Image {
        path: input.to_path_buf(),
        reason,
    };
    let image = image_file::parse(input, bytes)?;
    let trailing = image_file::trailing_bytes(bytes, &image);
    if trailing != 0 {
        return Err(trailing_error(input, trailing));
    }

    let mut area = UnprotectedArea::from_image(&image);
    if !replace {
        if area.keelsign_count() > 0 {
            return Err(Error::AlreadySigned {
                path: input.to_path_buf(),
                what: "keelsign TLVs",
            });
        }
        if hybrid && area.ed25519_count() > 0 {
            return Err(Error::AlreadySigned {
                path: input.to_path_buf(),
                what: "an Ed25519 KEYHASH + ED25519 pair",
            });
        }
    }
    area.strip_keelsign();
    if hybrid {
        area.strip_ed25519_pairs();
    }

    let encoded = area.encode().map_err(|len| too_large(input, len))?;
    let candidate = image_file::rebuild(bytes, &image, &encoded)?;
    match image_file::precheck(&candidate) {
        Precheck::Ready => {}
        Precheck::Rejected(reason) => return Err(rejected(format!("cannot be signed: {reason}"))),
        Precheck::Other(e) => {
            return Err(Error::Internal(format!(
                "unexpected result checking the image before signing: {e}"
            )));
        }
    }
    let candidate_image = image_file::parse(input, &candidate)?;
    let m = image_file::digest(&candidate, &candidate_image)?;
    Ok(Prepared { image, area, m })
}

/// Sign a [`Prepared`] image with `pq` (an LMS/HSS key with the leaf of `reservation`)
/// and, for a hybrid image, `ed`, then append the TLVs. Returns the signed image (not yet
/// self-checked) and the report.
pub fn sign_prepared(
    input: &Path,
    bytes: &[u8],
    prepared: Prepared<'_>,
    pq: &PrivateKey,
    ed: Option<&PrivateKey>,
    reservation: Option<&Reservation>,
) -> Result<(Vec<u8>, SignReport), Error> {
    let Prepared { image, mut area, m } = prepared;
    let keyhash = match ed {
        Some(ed) => {
            let (keyhash, signature) = sign_ed25519(ed, &m)?;
            area.push(IMAGE_TLV_KEYHASH, keyhash.to_vec());
            area.push(IMAGE_TLV_ED25519, signature);
            Some(keyhash)
        }
        None => None,
    };
    let algorithm = pq_algorithm(pq)?;
    let key_id = key_id_of(&pq.raw_public_key());
    area.push(TLV_KEELSIGN_KEY_ID, key_id.to_vec());
    area.push(algorithm.tlv_type(), sign_pq(pq, &m, reservation)?);

    let encoded = area.encode().map_err(|len| too_large(input, len))?;
    let signed = image_file::rebuild(bytes, &image, &encoded)?;
    let report = SignReport {
        algorithm: pq.algorithm(),
        key_id,
        keyhash,
        digest: m,
        output_len: signed.len(),
        input_len: bytes.len(),
        leaf: reservation.map(|r| LeafReport {
            index: r.leaf,
            total: r.leaves,
            state_path: r.state_path.clone(),
        }),
    };
    Ok((signed, report))
}

/// Sign the image `bytes` (read from `input`, for messages) with the ML-DSA key `pq` and,
/// for a hybrid image, `ed` ([`prepare_image`] then [`sign_prepared`]). LMS/HSS keys
/// sign through [`run`], which reserves their leaf. Returns the signed image (not yet
/// self-checked) and the report.
pub fn sign_image(
    input: &Path,
    bytes: &[u8],
    pq: &PrivateKey,
    ed: Option<&PrivateKey>,
    replace: bool,
) -> Result<(Vec<u8>, SignReport), Error> {
    let prepared = prepare_image(input, bytes, ed.is_some(), replace)?;
    sign_prepared(input, bytes, prepared, pq, ed, None)
}

/// Verify `signed` with `keelsign_verify::verify` against the signing keys: under
/// `PqOnly`, and also `Hybrid` when `ed` is given. Any failure is an internal error.
pub fn self_check(signed: &[u8], pq: &PrivateKey, ed: Option<&PrivateKey>) -> Result<(), Error> {
    let pq_public = pq.raw_public_key();
    let pq_key = TrustedKey {
        algorithm: pq_algorithm(pq)?,
        public_key: &pq_public,
    };
    let ed_public: Option<[u8; 32]> = match ed {
        Some(PrivateKey::Ed25519(k)) => Some(k.verifying_key().to_bytes()),
        Some(_) => return Err(Error::Internal("not an Ed25519 key".into())),
        None => None,
    };
    let ed_keys: Vec<Ed25519Key<'_>> = ed_public
        .iter()
        .map(|public_key| Ed25519Key { public_key })
        .collect();
    let keys = TrustedKeys::<1, 1>::with_ed25519(&[pq_key], &ed_keys)
        .map_err(|e| Error::Internal(format!("could not build the key set: {e}")))?;
    let mut policies = vec![Policy::PqOnly];
    if ed.is_some() {
        policies.push(Policy::Hybrid);
    }
    for policy in policies {
        let mut reader: &[u8] = signed;
        let mut tlv_buf = vec![0u8; signed.len()];
        let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
        keelsign_verify::verify(&mut reader, &keys, policy, &mut tlv_buf, &mut chunk).map_err(
            |e| {
                Error::Internal(format!(
                    "the signed image does not verify ({policy:?}): {e}"
                ))
            },
        )?;
    }
    Ok(())
}

/// Self-check `signed` (see [`self_check`]) and only then write it to `output`; on
/// failure nothing is written.
pub fn check_and_write(
    output: &Path,
    signed: &[u8],
    pq: &PrivateKey,
    ed: Option<&PrivateKey>,
    force: bool,
) -> Result<(), Error> {
    self_check(signed, pq, ed)?;
    keyfile::write_image(output, signed, force)
}

/// Run `keelsign sign`: check the paths, read the image and keys, sign, self-check and
/// write. `passphrase` is the shared `--passphrase-file` / `--passphrase-env` value.
pub fn run(
    request: &SignRequest,
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> Result<SignReport, Error> {
    if keyfile::same_file(&request.input, &request.output) {
        return Err(Error::Usage(format!(
            "OUT {} is the input image IN {}; write the signed image to a new file",
            request.output.display(),
            request.input.display()
        )));
    }
    for (option, key) in std::iter::once(("--key", &request.key))
        .chain(request.hybrid_key.iter().map(|k| ("--hybrid-key", k)))
    {
        if keyfile::same_file(key, &request.output) {
            return Err(Error::Usage(format!(
                "OUT {} is the key file {option} {}; refusing to replace a private key",
                request.output.display(),
                key.display()
            )));
        }
    }
    keyfile::ensure_absent(&request.output, request.force)?;

    let bytes = image_file::read_image(&request.input)?;
    // Reject a malformed or padded image before reading the keys.
    let image = image_file::parse(&request.input, &bytes)?;
    let trailing = image_file::trailing_bytes(&bytes, &image);
    if trailing != 0 {
        return Err(trailing_error(&request.input, trailing));
    }
    let (pq, ed) = load_keys(
        &request.key,
        request.hybrid_key.as_deref(),
        passphrase.map(|p| p.as_slice()),
    )?;
    let prepared = prepare_image(&request.input, &bytes, ed.is_some(), request.replace)?;
    // An LMS/HSS key reserves its leaf now: after the image parses, the keys load and M
    // is known, before any signature is computed. The reservation holds the key's lock
    // until the signed image is written.
    let reservation = match pq.as_lms() {
        Some(key) => Some(crate::lms_state::reserve(&request.key, key)?),
        None => None,
    };
    let (signed, report) = sign_prepared(
        &request.input,
        &bytes,
        prepared,
        &pq,
        ed.as_ref(),
        reservation.as_ref(),
    )?;
    check_and_write(&request.output, &signed, &pq, ed.as_ref(), request.force)?;
    drop(reservation);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keelsign_verify::image::Image;

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/images")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn key(alg: KeyAlgorithm) -> PrivateKey {
        let spec = match alg {
            KeyAlgorithm::MlDsa44 => crate::keys::KeySpec::MlDsa44,
            KeyAlgorithm::MlDsa65 => crate::keys::KeySpec::MlDsa65,
            KeyAlgorithm::Ed25519 => crate::keys::KeySpec::Ed25519,
            KeyAlgorithm::LmsHss => panic!("LMS keys need a parameter set"),
        };
        PrivateKey::generate(spec).expect("generate")
    }

    #[test]
    fn signs_in_memory_and_appends_in_order() {
        let input = fixture("mcuboot-ed25519.bin");
        let pq = key(KeyAlgorithm::MlDsa65);
        let (signed, report) =
            sign_image(Path::new("in.bin"), &input, &pq, None, false).expect("sign");
        self_check(&signed, &pq, None).expect("verifies");
        let image = Image::parse(&signed).expect("parse");
        let types: Vec<u16> = image.unprotected().iter().map(|t| t.tlv_type).collect();
        assert_eq!(types, [0x10, 0x01, 0x24, 0x4BA0, 0x4BA2]);
        assert_eq!(report.output_len, signed.len());
        assert_eq!(report.keyhash, None);
        assert_eq!(report.algorithm, KeyAlgorithm::MlDsa65);
        let lines = report.lines(Path::new("out.bin"));
        assert_eq!(lines[0], "algorithm: ml-dsa-65");
        assert!(lines[3].starts_with("signed: out.bin ("), "{lines:?}");
        assert!(lines[3].contains(" bytes, +"), "{lines:?}");
    }

    #[test]
    fn spent_leaf_message_names_the_next_leaf_or_exhaustion() {
        let state = Path::new("k.pem.state");
        let middle = spent_leaf_message(5, 1024, state);
        assert!(middle.contains("leaf 5 is reserved in k.pem.state and is now spent"));
        assert!(middle.contains("the next sign uses leaf 6"), "{middle}");
        let last = spent_leaf_message(1023, 1024, state);
        assert!(last.contains("leaf 1023 is reserved"), "{last}");
        assert!(last.contains("the key is now exhausted"), "{last}");
        assert!(!last.contains("leaf 1024"), "{last}");
    }

    #[test]
    fn self_check_rejects_a_tampered_image() {
        let input = fixture("mcuboot-ed25519.bin");
        let pq = key(KeyAlgorithm::MlDsa44);
        let ed = key(KeyAlgorithm::Ed25519);
        let (mut signed, _) =
            sign_image(Path::new("in.bin"), &input, &pq, Some(&ed), true).expect("sign");
        self_check(&signed, &pq, Some(&ed)).expect("verifies");
        // Flip a byte of the ML-DSA signature (the last TLV).
        let last = signed.len() - 1;
        signed[last] ^= 1;
        let err = self_check(&signed, &pq, Some(&ed)).expect_err("tampered");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("does not verify"), "{err}");
    }
}
