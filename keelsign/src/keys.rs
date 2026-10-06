//! Key generation and key file encodings (see `docs/keys.md`).
//!
//! - Private keys: PKCS#8 v1 `PrivateKeyInfo` (RFC 5208 / RFC 5958), PEM label
//!   `PRIVATE KEY` or DER. ML-DSA keys use the RFC 9881 §6 `seed` form; Ed25519 keys the
//!   RFC 8410 §7 v1 layout (no public key), which imgtool reads. LMS/HSS keys use the
//!   RFC 8708 algorithm `id-alg-hss-lms-hashsig` (parameters absent) with keelsign's
//!   private-key blob ([`HssPrivateKey::to_blob`]) as `privateKey`; they are stateful
//!   and come with a state file and a journal (`crate::lms_state`).
//! - Encrypted private keys: PKCS#8 `EncryptedPrivateKeyInfo`, PBES2 with scrypt
//!   (N = 2^14, r = 8, p = 1, 16-byte salt) and AES-256-CBC, PEM label
//!   `ENCRYPTED PRIVATE KEY` or DER.
//! - Public keys: `SubjectPublicKeyInfo` (RFC 5280), PEM label `PUBLIC KEY` or DER.
//!   [`PublicKey::from_bytes`] reads them for `verify --pub`: ML-DSA-44/65 (RFC 9881),
//!   Ed25519 (RFC 8410) and HSS/LMS (RFC 8708).

use crate::error::{Error, KeyFileError};
use crate::lms_sign::{HssCaches, HssPrivateKey, LmsError, LmsParams};
use ml_dsa::{Keypair as _, MlDsa44, MlDsa65};
use pkcs8::der::asn1::AnyRef;
use pkcs8::der::asn1::OctetStringRef;
use pkcs8::der::pem::PemLabel as _;
use pkcs8::der::{Decode as _, Document, Encode as _, Reader as _, SecretDocument};
use pkcs8::spki::ObjectIdentifier;
use pkcs8::{
    AlgorithmIdentifierRef, EncodePrivateKey as _, EncodePublicKey as _,
    EncryptedPrivateKeyInfoRef, LineEnding, PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
};
use std::fmt;
use zeroize::Zeroizing;

/// `id-ml-dsa-44` (NIST CSOR `sigAlgs 17`; RFC 9881 §2).
pub const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
/// `id-ml-dsa-65` (NIST CSOR `sigAlgs 18`; RFC 9881 §2).
pub const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
/// `id-Ed25519` (RFC 8410 §3).
pub const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `id-alg-hss-lms-hashsig` (RFC 8708 §3): keelsign's LMS/HSS key files and the HSS/LMS
/// public keys `verify --pub` reads.
pub const ID_HSS_LMS_HASHSIG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.17");

/// PEM label of a PKCS#8 private key.
pub const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";
/// PEM label of a PKCS#8 encrypted private key.
pub const PEM_ENCRYPTED_PRIVATE_KEY: &str = "ENCRYPTED PRIVATE KEY";
/// PEM label of a `SubjectPublicKeyInfo`.
pub const PEM_PUBLIC_KEY: &str = "PUBLIC KEY";

/// A signature algorithm keelsign generates keys for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// Ed25519 (RFC 8032), the classical half of a hybrid image.
    Ed25519,
    /// LMS/HSS (RFC 8554, SP 800-208): stateful hash-based signatures.
    LmsHss,
}

impl KeyAlgorithm {
    /// All algorithms, in CLI order.
    pub const ALL: [Self; 4] = [Self::MlDsa44, Self::MlDsa65, Self::Ed25519, Self::LmsHss];

    /// The name: `ml-dsa-44`, `ml-dsa-65`, `ed25519` or `lms-hss`.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::Ed25519 => "ed25519",
            Self::LmsHss => "lms-hss",
        }
    }

    /// The algorithm OID used in the key files.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::MlDsa44 => ID_ML_DSA_44,
            Self::MlDsa65 => ID_ML_DSA_65,
            Self::Ed25519 => ID_ED25519,
            Self::LmsHss => ID_HSS_LMS_HASHSIG,
        }
    }
}

/// What kind of key [`PrivateKey::generate`] makes: an algorithm and, for LMS/HSS, the
/// tree height and the number of HSS levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySpec {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// Ed25519.
    Ed25519,
    /// LMS/HSS with `levels` (1 or 2) levels of `params` (LMOTS_SHA256_N32_W8).
    LmsHss {
        /// The LMS parameter set of every level (its tree height).
        params: LmsParams,
        /// The number of HSS levels, 1 or 2.
        levels: u8,
    },
}

impl KeySpec {
    /// The algorithm of the key.
    pub fn algorithm(self) -> KeyAlgorithm {
        match self {
            Self::MlDsa44 => KeyAlgorithm::MlDsa44,
            Self::MlDsa65 => KeyAlgorithm::MlDsa65,
            Self::Ed25519 => KeyAlgorithm::Ed25519,
            Self::LmsHss { .. } => KeyAlgorithm::LmsHss,
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How a key is identified in a keelsign image (docs/image-format.md, Key ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyIdentity {
    /// ML-DSA: the first 16 bytes of SHA-256 over the FIPS 204 public key encoding.
    KeyId([u8; 16]),
    /// Ed25519: MCUboot's KEYHASH, SHA-256 over the DER `SubjectPublicKeyInfo`.
    KeyHash([u8; 32]),
}

impl fmt::Display for KeyIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyId(id) => write!(f, "key id: {}", hex(id)),
            Self::KeyHash(hash) => write!(f, "keyhash: {}", hex(hash)),
        }
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A private signing key of one of the [`KeyAlgorithm`]s. Key material is zeroized on
/// drop.
pub enum PrivateKey {
    /// An ML-DSA-44 key (held as its seed).
    MlDsa44(Box<ml_dsa::SigningKey<MlDsa44>>),
    /// An ML-DSA-65 key (held as its seed).
    MlDsa65(Box<ml_dsa::SigningKey<MlDsa65>>),
    /// An Ed25519 key.
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// An LMS/HSS key (stateful: see `crate::lms_state`).
    LmsHss(Box<HssPrivateKey>),
}

fn lms_key_error(e: LmsError) -> KeyFileError {
    match e {
        LmsError::Unsupported(reason) => KeyFileError::Unsupported(reason),
        other => KeyFileError::Corrupt(other.to_string()),
    }
}

fn encode_err(e: impl fmt::Display) -> Error {
    Error::Encode(e.to_string())
}

impl PrivateKey {
    /// Generate a new key from operating-system randomness: 32 bytes for ML-DSA (the
    /// seed ξ) and Ed25519 (the secret key); `SEED` and `I` per level for LMS/HSS (see
    /// [`Self::generate_with_caches`], which also returns the LMS tree caches).
    pub fn generate(spec: KeySpec) -> Result<Self, Error> {
        Self::generate_with_caches(spec).map(|(key, _)| key)
    }

    /// [`Self::generate`], also returning an LMS/HSS key's tree caches (the start of its
    /// state file; `None` for the other algorithms). An LMS/HSS key computes its whole
    /// top tree (and, with two levels, its first bottom tree): an H20 tree takes minutes.
    pub fn generate_with_caches(spec: KeySpec) -> Result<(Self, Option<HssCaches>), Error> {
        let algorithm = match spec {
            KeySpec::LmsHss { params, levels } => {
                let (key, caches) =
                    HssPrivateKey::generate(params, levels, crate::lms_sign::DEFAULT_CACHE_FLOOR)
                        .map_err(|e| match e {
                        LmsError::Rng(e) => Error::Rng(e),
                        other => Error::Usage(other.to_string()),
                    })?;
                return Ok((Self::LmsHss(Box::new(key)), Some(caches)));
            }
            other => other.algorithm(),
        };
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|e| Error::Rng(e.to_string()))?;
        Self::from_seed(algorithm, &seed).map(|key| (key, None))
    }

    /// The key derived from a 32-byte seed (ML-DSA ξ or the Ed25519 secret key).
    fn from_seed(algorithm: KeyAlgorithm, seed: &[u8; 32]) -> Result<Self, Error> {
        Ok(match algorithm {
            KeyAlgorithm::MlDsa44 => {
                Self::MlDsa44(Box::new(ml_dsa::SigningKey::from_seed(&(*seed).into())))
            }
            KeyAlgorithm::MlDsa65 => {
                Self::MlDsa65(Box::new(ml_dsa::SigningKey::from_seed(&(*seed).into())))
            }
            KeyAlgorithm::Ed25519 => {
                Self::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed)))
            }
            KeyAlgorithm::LmsHss => {
                return Err(Error::Internal(
                    "LMS/HSS keys are not derived from a single seed".into(),
                ));
            }
        })
    }

    /// The key's algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::MlDsa44(_) => KeyAlgorithm::MlDsa44,
            Self::MlDsa65(_) => KeyAlgorithm::MlDsa65,
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
            Self::LmsHss(_) => KeyAlgorithm::LmsHss,
        }
    }

    /// The parameter set, for example `ML-DSA-65`, `Ed25519` or
    /// `LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=1`.
    pub fn parameter_set(&self) -> String {
        match self {
            Self::MlDsa44(_) => "ML-DSA-44".into(),
            Self::MlDsa65(_) => "ML-DSA-65".into(),
            Self::Ed25519(_) => "Ed25519".into(),
            Self::LmsHss(k) => k.parameter_set(),
        }
    }

    /// The LMS/HSS key, if this is one.
    pub fn as_lms(&self) -> Option<&HssPrivateKey> {
        match self {
            Self::LmsHss(k) => Some(k),
            _ => None,
        }
    }

    /// The unencrypted PKCS#8 v1 DER encoding.
    pub fn to_pkcs8_der(&self) -> Result<SecretDocument, Error> {
        match self {
            // RFC 9881 §6 `seed [0] IMPLICIT OCTET STRING (SIZE (32))`.
            Self::MlDsa44(k) => k.to_pkcs8_der().map_err(encode_err),
            Self::MlDsa65(k) => k.to_pkcs8_der().map_err(encode_err),
            Self::Ed25519(k) => {
                // RFC 8410 §7 v1, no publicKey: what imgtool and Python cryptography
                // read (ed25519-dalek's own encoder writes v2).
                let seed = Zeroizing::new(k.to_bytes());
                let inner = Zeroizing::new(
                    OctetStringRef::new(seed.as_ref())
                        .and_then(|o| o.to_der())
                        .map_err(encode_err)?,
                );
                let private_key = OctetStringRef::new(&inner).map_err(encode_err)?;
                let pki = PrivateKeyInfoRef::new(ed25519_dalek::pkcs8::ALGORITHM_ID, private_key);
                SecretDocument::encode_msg(&pki).map_err(encode_err)
            }
            Self::LmsHss(k) => {
                // RFC 8708 algorithm, parameters absent; keelsign's blob as privateKey.
                let blob = k.to_blob();
                let private_key = OctetStringRef::new(&blob).map_err(encode_err)?;
                let algorithm = AlgorithmIdentifierRef {
                    oid: ID_HSS_LMS_HASHSIG,
                    parameters: None,
                };
                SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, private_key))
                    .map_err(encode_err)
            }
        }
    }

    /// The unencrypted PKCS#8 PEM encoding (label `PRIVATE KEY`, LF line endings).
    pub fn to_pem(&self) -> Result<Zeroizing<String>, Error> {
        self.to_pkcs8_der()?
            .to_pem(PEM_PRIVATE_KEY, LineEnding::LF)
            .map_err(encode_err)
    }

    /// The PKCS#8 `EncryptedPrivateKeyInfo` DER encoding under `passphrase` (PBES2,
    /// scrypt N = 2^14 r = 8 p = 1, AES-256-CBC, random salt and IV).
    pub fn to_encrypted_der(&self, passphrase: &[u8]) -> Result<SecretDocument, Error> {
        let der = self.to_pkcs8_der()?;
        PrivateKeyInfoRef::from_der(der.as_bytes())
            .map_err(encode_err)?
            .encrypt(passphrase)
            .map_err(encode_err)
    }

    /// The encrypted PEM encoding (label `ENCRYPTED PRIVATE KEY`, LF line endings).
    pub fn to_encrypted_pem(&self, passphrase: &[u8]) -> Result<Zeroizing<String>, Error> {
        self.to_encrypted_der(passphrase)?
            .to_pem(EncryptedPrivateKeyInfoRef::PEM_LABEL, LineEnding::LF)
            .map_err(encode_err)
    }

    /// The DER `SubjectPublicKeyInfo` of the public key. For LMS/HSS the
    /// `subjectPublicKey` BIT STRING holds the DER OCTET STRING of the 60-byte HSS public
    /// key (RFC 8708 §4), as [`PublicKey::from_bytes`] reads it.
    pub fn public_key_spki_der(&self) -> Result<Document, Error> {
        match self {
            Self::MlDsa44(k) => k.verifying_key().to_public_key_der(),
            Self::MlDsa65(k) => k.verifying_key().to_public_key_der(),
            Self::Ed25519(k) => k.verifying_key().to_public_key_der(),
            Self::LmsHss(k) => {
                let wrapped = OctetStringRef::new(k.public_key())
                    .and_then(|o| o.to_der())
                    .map_err(encode_err)?;
                let spki = SubjectPublicKeyInfoRef {
                    algorithm: AlgorithmIdentifierRef {
                        oid: ID_HSS_LMS_HASHSIG,
                        parameters: None,
                    },
                    subject_public_key: pkcs8::der::asn1::BitStringRef::from_bytes(&wrapped)
                        .map_err(encode_err)?,
                };
                return Document::encode_msg(&spki).map_err(encode_err);
            }
        }
        .map_err(encode_err)
    }

    /// The PEM `SubjectPublicKeyInfo` (label `PUBLIC KEY`, LF line endings).
    pub fn public_key_spki_pem(&self) -> Result<String, Error> {
        self.public_key_spki_der()?
            .to_pem(PEM_PUBLIC_KEY, LineEnding::LF)
            .map_err(encode_err)
    }

    /// The raw public key: the FIPS 204 encoding (1,312 / 1,952 bytes), the 32-byte
    /// Ed25519 key or the 60-byte HSS public key `u32 L || LMS public key`.
    pub fn raw_public_key(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(k) => k.verifying_key().encode().to_vec(),
            Self::MlDsa65(k) => k.verifying_key().encode().to_vec(),
            Self::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            Self::LmsHss(k) => k.public_key().to_vec(),
        }
    }

    /// The key ID (ML-DSA) or KEYHASH (Ed25519) that identifies this key in an image.
    pub fn identity(&self) -> KeyIdentity {
        match self {
            Self::MlDsa44(k) => KeyIdentity::KeyId(keelsign_verify::key_id_of(
                k.verifying_key().encode().as_slice(),
            )),
            Self::MlDsa65(k) => KeyIdentity::KeyId(keelsign_verify::key_id_of(
                k.verifying_key().encode().as_slice(),
            )),
            Self::Ed25519(k) => {
                KeyIdentity::KeyHash(keelsign_verify::keyhash_of(&k.verifying_key().to_bytes()))
            }
            Self::LmsHss(k) => KeyIdentity::KeyId(keelsign_verify::key_id_of(k.public_key())),
        }
    }

    /// Load a private key file's contents: PKCS#8 PEM or DER, encrypted or not.
    ///
    /// `passphrase` must be given exactly when the key is encrypted. Explanatory text
    /// before the PEM header (RFC 7468 §2) is ignored.
    pub fn from_bytes(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        let pem_start = std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.find("-----BEGIN ").map(|at| (text, at)));
        match pem_start {
            Some((text, at)) => Self::from_pem(text.get(at..).unwrap_or_default(), passphrase),
            None if bytes.is_empty() => Err(KeyFileError::Corrupt("the file is empty".into())),
            None => Self::from_der(bytes, passphrase),
        }
    }

    fn from_pem(pem: &str, passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        let (label, doc) = SecretDocument::from_pem(pem)
            .map_err(|e| KeyFileError::Corrupt(format!("invalid PEM: {e}")))?;
        match label {
            PEM_PRIVATE_KEY => {
                if passphrase.is_some() {
                    return Err(KeyFileError::PassphraseUnexpected);
                }
                let pki = PrivateKeyInfoRef::from_der(doc.as_bytes())
                    .map_err(|e| KeyFileError::Corrupt(format!("not a PKCS#8 private key: {e}")))?;
                Self::from_pki(&pki)
            }
            PEM_ENCRYPTED_PRIVATE_KEY => Self::from_encrypted(doc.as_bytes(), passphrase),
            PEM_PUBLIC_KEY => Err(public_key_given()),
            other => Err(KeyFileError::Unsupported(format!(
                "unsupported PEM label `{other}` (expected `{PEM_PRIVATE_KEY}` or \
                 `{PEM_ENCRYPTED_PRIVATE_KEY}`)"
            ))),
        }
    }

    fn from_der(der: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        let plain_err = match PrivateKeyInfoRef::from_der(der) {
            Ok(pki) => {
                if passphrase.is_some() {
                    return Err(KeyFileError::PassphraseUnexpected);
                }
                return Self::from_pki(&pki);
            }
            Err(e) => e,
        };
        if encryption_algorithm(der).is_ok() {
            return Self::from_encrypted(der, passphrase);
        }
        if SubjectPublicKeyInfoRef::from_der(der).is_ok() {
            return Err(public_key_given());
        }
        Err(KeyFileError::Corrupt(format!(
            "neither a PEM file nor a DER PKCS#8 private key: {plain_err}"
        )))
    }

    fn from_encrypted(der: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        // Check the scheme and bound the KDF cost before anything is derived: the
        // parameters come from the file, and pkcs5 / scrypt panic on some values (scrypt
        // N = 0) or would spend unbounded memory and time on others.
        let (scheme, params) = encryption_algorithm(der).map_err(|e| {
            KeyFileError::Corrupt(format!("not a PKCS#8 encrypted private key: {e}"))
        })?;
        check_pbes2_algorithms(scheme, params)?;
        let encrypted = EncryptedPrivateKeyInfoRef::from_der(der)
            .map_err(|e| KeyFileError::Corrupt(format!("malformed PBES2 parameters: {e}")))?;
        let pbes2 = encrypted
            .encryption_algorithm
            .pbes2()
            .ok_or_else(|| KeyFileError::Unsupported(UNSUPPORTED_SCHEME.into()))?;
        check_kdf_limits(&pbes2.kdf)?;
        let passphrase = passphrase.ok_or(KeyFileError::PassphraseRequired)?;
        // A wrong passphrase usually fails the CBC padding check (DecryptFailed), but
        // about 1 in 256 times it decrypts to garbage that then fails to parse: both
        // mean "wrong passphrase". Anything else is a broken file.
        let doc = encrypted.decrypt(passphrase).map_err(|e| match e {
            pkcs8::Error::EncryptedPrivateKey(pkcs8::pkcs5::Error::DecryptFailed)
            | pkcs8::Error::Asn1(_) => KeyFileError::WrongPassphrase,
            other => KeyFileError::Corrupt(format!("cannot decrypt the key: {other}")),
        })?;
        let pki = PrivateKeyInfoRef::from_der(doc.as_bytes())
            .map_err(|_| KeyFileError::WrongPassphrase)?;
        Self::from_pki(&pki)
    }

    fn from_pki(pki: &PrivateKeyInfoRef<'_>) -> Result<Self, KeyFileError> {
        let oid = pki.algorithm.oid;
        let algorithm = KeyAlgorithm::ALL
            .into_iter()
            .find(|a| a.oid() == oid)
            .ok_or_else(|| {
                KeyFileError::Unsupported(format!(
                    "unsupported key algorithm OID {oid} (keelsign reads ML-DSA-44 \
                     {ID_ML_DSA_44}, ML-DSA-65 {ID_ML_DSA_65}, Ed25519 {ID_ED25519} and \
                     HSS/LMS {ID_HSS_LMS_HASHSIG})"
                ))
            })?;
        if pki.algorithm.parameters.is_some() {
            return Err(KeyFileError::Corrupt(format!(
                "{algorithm} AlgorithmIdentifier has parameters; they must be absent \
                 (RFC 9881 §2, RFC 8410 §3, RFC 8708 §3)"
            )));
        }
        match algorithm {
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 => {
                match pki.private_key.as_bytes().first() {
                    Some(0x80) => {}
                    Some(0x04 | 0x30) => {
                        return Err(KeyFileError::Unsupported(
                            "ML-DSA private key is in RFC 9881 `expandedKey`/`both` form; \
                             keelsign reads the seed form; convert with `openssl pkey -in K \
                             -provparam ml-dsa.output_formats=seed-only -out K.seed.pem`"
                                .into(),
                        ));
                    }
                    _ => {
                        return Err(KeyFileError::Corrupt(
                            "ML-DSA private key is not an RFC 9881 seed, expandedKey or both"
                                .into(),
                        ));
                    }
                }
                let bad = |e: pkcs8::Error| {
                    KeyFileError::Corrupt(format!("invalid {algorithm} seed private key: {e}"))
                };
                let key = if algorithm == KeyAlgorithm::MlDsa44 {
                    ml_dsa::SigningKey::<MlDsa44>::try_from(pki.clone())
                        .map(|k| Self::MlDsa44(Box::new(k)))
                        .map_err(bad)?
                } else {
                    ml_dsa::SigningKey::<MlDsa65>::try_from(pki.clone())
                        .map(|k| Self::MlDsa65(Box::new(k)))
                        .map_err(bad)?
                };
                // ml-dsa ignores a PKCS#8 v2 publicKey; it must match the seed.
                if let Some(public_key) = &pki.public_key
                    && public_key.as_bytes() != Some(key.raw_public_key().as_slice())
                {
                    return Err(KeyFileError::Corrupt(
                        "the public key in the file does not match the private key".into(),
                    ));
                }
                Ok(key)
            }
            KeyAlgorithm::Ed25519 => ed25519_dalek::SigningKey::try_from(pki.clone())
                .map(|k| Self::Ed25519(Box::new(k)))
                .map_err(|e| {
                    KeyFileError::Corrupt(format!(
                        "invalid Ed25519 private key (or its public key does not match): {e}"
                    ))
                }),
            KeyAlgorithm::LmsHss => {
                let key =
                    HssPrivateKey::from_blob(pki.private_key.as_bytes()).map_err(lms_key_error)?;
                // A PKCS#8 v2 publicKey, if present, must be the blob's public key.
                if let Some(public_key) = &pki.public_key
                    && public_key.as_bytes() != Some(key.public_key().as_slice())
                {
                    return Err(KeyFileError::Corrupt(
                        "the public key in the file does not match the private key".into(),
                    ));
                }
                Ok(Self::LmsHss(Box::new(key)))
            }
        }
    }
}

/// A public key read from a `SubjectPublicKeyInfo` file (`verify --pub`): the raw key the
/// device trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An ML-DSA-44 public key (FIPS 204 encoding, 1,312 bytes).
    MlDsa44(Vec<u8>),
    /// An ML-DSA-65 public key (FIPS 204 encoding, 1,952 bytes).
    MlDsa65(Vec<u8>),
    /// An Ed25519 public key (32 bytes).
    Ed25519([u8; 32]),
    /// An HSS/LMS public key, `u32 L || LMS public key` (RFC 8554 §6.1; 52 or 60 bytes).
    LmsHss(Vec<u8>),
}

impl PublicKey {
    /// Load a public key file's contents: a `SubjectPublicKeyInfo` as PEM (label
    /// `PUBLIC KEY`; text before the header is ignored) or DER.
    ///
    /// The `AlgorithmIdentifier` must be `id-ml-dsa-44`, `id-ml-dsa-65`, `id-Ed25519` or
    /// `id-alg-hss-lms-hashsig` with parameters absent. For HSS/LMS the `subjectPublicKey`
    /// BIT STRING holds the DER OCTET STRING of the HSS public key (RFC 8708 §4, following
    /// RFC 5912's `PUBLIC-KEY` convention); for the others it holds the raw key. A private
    /// key file is refused as corrupt ("holds a private key").
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyFileError> {
        let pem_start = std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.find("-----BEGIN ").map(|at| (text, at)));
        match pem_start {
            Some((text, at)) => Self::from_pem(text.get(at..).unwrap_or_default()),
            None if bytes.is_empty() => Err(KeyFileError::Corrupt("the file is empty".into())),
            None => Self::from_der(bytes),
        }
    }

    fn from_pem(pem: &str) -> Result<Self, KeyFileError> {
        // Look at the label before decoding, so a private key is never decoded here.
        let label = pkcs8::der::pem::decode_label(pem.as_bytes())
            .map_err(|e| KeyFileError::Corrupt(format!("invalid PEM: {e}")))?;
        match label {
            PEM_PUBLIC_KEY => {}
            PEM_PRIVATE_KEY | PEM_ENCRYPTED_PRIVATE_KEY => return Err(private_key_given()),
            other => {
                return Err(KeyFileError::Unsupported(format!(
                    "unsupported PEM label `{other}` (expected `{PEM_PUBLIC_KEY}`)"
                )));
            }
        }
        let (_, doc) = Document::from_pem(pem)
            .map_err(|e| KeyFileError::Corrupt(format!("invalid PEM: {e}")))?;
        let spki = SubjectPublicKeyInfoRef::from_der(doc.as_bytes()).map_err(|e| {
            KeyFileError::Corrupt(format!("not a SubjectPublicKeyInfo public key: {e}"))
        })?;
        Self::from_spki(&spki)
    }

    fn from_der(der: &[u8]) -> Result<Self, KeyFileError> {
        match SubjectPublicKeyInfoRef::from_der(der) {
            Ok(spki) => Self::from_spki(&spki),
            Err(e) => {
                if PrivateKeyInfoRef::from_der(der).is_ok() || encryption_algorithm(der).is_ok() {
                    Err(private_key_given())
                } else {
                    Err(KeyFileError::Corrupt(format!(
                        "neither a PEM file nor a DER SubjectPublicKeyInfo: {e}"
                    )))
                }
            }
        }
    }

    fn from_spki(spki: &SubjectPublicKeyInfoRef<'_>) -> Result<Self, KeyFileError> {
        let oid = spki.algorithm.oid;
        let name = match oid {
            ID_ML_DSA_44 => "ML-DSA-44",
            ID_ML_DSA_65 => "ML-DSA-65",
            ID_ED25519 => "Ed25519",
            ID_HSS_LMS_HASHSIG => "HSS/LMS",
            _ => {
                return Err(KeyFileError::Unsupported(format!(
                    "unsupported public key algorithm OID {oid} (keelsign reads ML-DSA-44 \
                     {ID_ML_DSA_44}, ML-DSA-65 {ID_ML_DSA_65}, Ed25519 {ID_ED25519} and \
                     HSS/LMS {ID_HSS_LMS_HASHSIG})"
                )));
            }
        };
        if spki.algorithm.parameters.is_some() {
            return Err(KeyFileError::Corrupt(format!(
                "{name} AlgorithmIdentifier has parameters; they must be absent (RFC 9881 \
                 §2, RFC 8410 §3, RFC 8708 §3)"
            )));
        }
        let bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
            KeyFileError::Corrupt(format!(
                "{name} subjectPublicKey is not a whole number of bytes"
            ))
        })?;
        let wrong_length = |expected: &str| {
            KeyFileError::Corrupt(format!(
                "{name} public key is {} bytes; it must be {expected}",
                bits.len()
            ))
        };
        match oid {
            ID_ML_DSA_44 if bits.len() == 1312 => Ok(Self::MlDsa44(bits.to_vec())),
            ID_ML_DSA_44 => Err(wrong_length("1,312")),
            ID_ML_DSA_65 if bits.len() == 1952 => Ok(Self::MlDsa65(bits.to_vec())),
            ID_ML_DSA_65 => Err(wrong_length("1,952")),
            ID_ED25519 => bits
                .try_into()
                .map(Self::Ed25519)
                .map_err(|_| wrong_length("32")),
            _ => {
                // RFC 8708 §4: the BIT STRING holds the DER encoding of
                // `HSS-LMS-HashSig-PublicKey ::= OCTET STRING`.
                let key = <&OctetStringRef>::from_der(bits).map_err(|e| {
                    KeyFileError::Corrupt(format!(
                        "HSS/LMS subjectPublicKey is not a DER OCTET STRING (RFC 8708 §4): {e}"
                    ))
                })?;
                let key = key.as_bytes();
                if !keelsign_verify::lms::PUBLIC_KEY_LENS.contains(&key.len()) {
                    return Err(KeyFileError::Corrupt(format!(
                        "HSS/LMS public key is {} bytes; it must be 52 or 60",
                        key.len()
                    )));
                }
                keelsign_verify::lms::check_public_key(key).map_err(|e| {
                    KeyFileError::Corrupt(format!("invalid HSS/LMS public key: {e}"))
                })?;
                Ok(Self::LmsHss(key.to_vec()))
            }
        }
    }

    /// The algorithm name: `ml-dsa-44`, `ml-dsa-65`, `ed25519` or `lms-hss`.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MlDsa44(_) => "ml-dsa-44",
            Self::MlDsa65(_) => "ml-dsa-65",
            Self::Ed25519(_) => "ed25519",
            Self::LmsHss(_) => "lms-hss",
        }
    }

    /// The raw public key.
    pub fn raw(&self) -> &[u8] {
        match self {
            Self::MlDsa44(k) | Self::MlDsa65(k) | Self::LmsHss(k) => k,
            Self::Ed25519(k) => k,
        }
    }

    /// The key ID (post-quantum keys) or KEYHASH (Ed25519) that identifies this key in an
    /// image.
    pub fn identity(&self) -> KeyIdentity {
        match self {
            Self::Ed25519(k) => KeyIdentity::KeyHash(keelsign_verify::keyhash_of(k)),
            other => KeyIdentity::KeyId(keelsign_verify::key_id_of(other.raw())),
        }
    }

    /// The trusted post-quantum key, or `None` for an Ed25519 key.
    pub fn trusted_key(&self) -> Option<keelsign_verify::TrustedKey<'_>> {
        let algorithm = match self {
            Self::MlDsa44(_) => keelsign_verify::Algorithm::MlDsa44,
            Self::MlDsa65(_) => keelsign_verify::Algorithm::MlDsa65,
            Self::LmsHss(_) => keelsign_verify::Algorithm::LmsHss,
            Self::Ed25519(_) => return None,
        };
        Some(keelsign_verify::TrustedKey {
            algorithm,
            public_key: self.raw(),
        })
    }

    /// The trusted Ed25519 key, or `None` for a post-quantum key.
    pub fn ed25519_key(&self) -> Option<keelsign_verify::Ed25519Key<'_>> {
        match self {
            Self::Ed25519(public_key) => Some(keelsign_verify::Ed25519Key { public_key }),
            _ => None,
        }
    }
}

/// The message for an encryption scheme keelsign does not read.
const UNSUPPORTED_SCHEME: &str =
    "unsupported encryption scheme; keelsign reads PBES2 (scrypt or PBKDF2 with AES-CBC)";

/// Largest scrypt cost N accepted when decrypting (keelsign writes 2^14).
pub const MAX_SCRYPT_N: u64 = 1 << 20;
/// Largest scrypt block size r accepted when decrypting (keelsign writes 8).
pub const MAX_SCRYPT_R: u16 = 32;
/// Largest scrypt parallelization p accepted when decrypting (keelsign writes 1).
pub const MAX_SCRYPT_P: u16 = 16;
/// Largest PBKDF2 iteration count accepted when decrypting.
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// Largest scrypt memory, 128 * r * N bytes, accepted when decrypting (256 MiB; keelsign
/// writes 16 MiB).
pub const MAX_SCRYPT_MEMORY: u64 = 256 << 20;

/// The `encryptionAlgorithm` OID and parameters of a DER `EncryptedPrivateKeyInfo`
/// (`SEQUENCE { AlgorithmIdentifier, OCTET STRING }`), whatever the scheme.
fn encryption_algorithm(
    der: &[u8],
) -> Result<(ObjectIdentifier, Option<AnyRef<'_>>), pkcs8::der::Error> {
    AnyRef::from_der(der)?.sequence(|reader| {
        let algorithm: AlgorithmIdentifierRef<'_> = reader.decode()?;
        let _data: &OctetStringRef = reader.decode()?;
        Ok((algorithm.oid, algorithm.parameters))
    })
}

/// PBES2 with scrypt or PBKDF2 and AES-CBC, or `Unsupported`.
fn check_pbes2_algorithms(
    scheme: ObjectIdentifier,
    params: Option<AnyRef<'_>>,
) -> Result<(), KeyFileError> {
    use pkcs8::pkcs5::pbes2;
    let unsupported = || KeyFileError::Unsupported(UNSUPPORTED_SCHEME.into());
    if scheme != pbes2::PBES2_OID {
        return Err(unsupported());
    }
    let params = params.ok_or_else(|| KeyFileError::Corrupt("PBES2 without parameters".into()))?;
    let (kdf, cipher) = params
        .sequence(|reader| {
            let kdf: AlgorithmIdentifierRef<'_> = reader.decode()?;
            let cipher: AlgorithmIdentifierRef<'_> = reader.decode()?;
            Ok::<_, pkcs8::der::Error>((kdf.oid, cipher.oid))
        })
        .map_err(|e| KeyFileError::Corrupt(format!("malformed PBES2 parameters: {e}")))?;
    let kdf_ok = kdf == pbes2::SCRYPT_OID || kdf == pbes2::PBKDF2_OID;
    let cipher_ok = [
        pbes2::AES_128_CBC_OID,
        pbes2::AES_192_CBC_OID,
        pbes2::AES_256_CBC_OID,
    ]
    .contains(&cipher);
    if kdf_ok && cipher_ok {
        Ok(())
    } else {
        Err(unsupported())
    }
}

/// Bound the KDF cost taken from the file (see `docs/keys.md`, Passphrase encryption).
fn check_kdf_limits(kdf: &pkcs8::pkcs5::pbes2::Kdf) -> Result<(), KeyFileError> {
    let out_of_range = |what: String| {
        KeyFileError::Unsupported(format!("{what} is outside the range keelsign accepts"))
    };
    if let Some(scrypt) = kdf.scrypt() {
        let n = scrypt.cost_parameter;
        if !(n.is_power_of_two() && (2..=MAX_SCRYPT_N).contains(&n)) {
            return Err(out_of_range(format!(
                "scrypt cost N = {n} (must be a power of two from 2 to 2^20)"
            )));
        }
        let (r, p) = (scrypt.block_size, scrypt.parallelization);
        if !(1..=MAX_SCRYPT_R).contains(&r) {
            return Err(out_of_range(format!("scrypt block size r = {r} (1 to 32)")));
        }
        if !(1..=MAX_SCRYPT_P).contains(&p) {
            return Err(out_of_range(format!(
                "scrypt parallelization p = {p} (1 to 16)"
            )));
        }
        // N <= 2^20 and r <= 32 here, so this cannot overflow.
        let memory = 128 * u64::from(r) * n;
        if memory > MAX_SCRYPT_MEMORY {
            return Err(KeyFileError::Unsupported(format!(
                "scrypt needs 128·r·N = {} MiB of memory (r = {r}, N = {n}), more than the \
                 256 MiB keelsign accepts",
                memory >> 20
            )));
        }
    } else if let Some(pbkdf2) = kdf.pbkdf2() {
        let i = pbkdf2.iteration_count;
        if !(1..=MAX_PBKDF2_ITERATIONS).contains(&i) {
            return Err(out_of_range(format!(
                "PBKDF2 iteration count {i} (1 to 10,000,000)"
            )));
        }
        if pbkdf2.prf != pkcs8::pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256 {
            return Err(KeyFileError::Unsupported(
                "unsupported PBKDF2 PRF; keelsign reads HMAC-SHA-256".into(),
            ));
        }
    } else {
        return Err(KeyFileError::Unsupported(UNSUPPORTED_SCHEME.into()));
    }
    Ok(())
}

fn public_key_given() -> KeyFileError {
    KeyFileError::Corrupt("it holds a public key, not a private key".into())
}

fn private_key_given() -> KeyFileError {
    KeyFileError::Corrupt("it holds a private key, not a public key".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::der::asn1::BitStringRef;

    /// RFC 8410 §10.1: an Ed25519 public key and its KEYHASH.
    const RFC8410_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
";
    const RFC8410_KEYHASH: &str =
        "a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f";

    /// RFC 9881 Appendix C.1: the seed 00 01 .. 1f; Appendix C.2: SHA-256 of the DER SPKI
    /// of the ML-DSA-44 and ML-DSA-65 public keys for it, and their keelsign key IDs.
    const RFC9881_SPKI_SHA256: [&str; 2] = [
        "837832708c5236d951581f1fddf2b79991b3424a0486d16da1ddad0fd69701be",
        "b8b62131bfbe84433efb2273d7f5b87f7a22854a2cfd366fc2aead86d837c52d",
    ];
    const RFC9881_KEY_IDS: [&str; 2] = [
        "9f107644c1084526af3bc8098680b054",
        "d666806e11cee19a7c989f7445f90dd4",
    ];

    fn spki_der(oid: ObjectIdentifier, parameters: Option<AnyRef<'_>>, key: &[u8]) -> Vec<u8> {
        let spki = SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef { oid, parameters },
            subject_public_key: BitStringRef::from_bytes(key).expect("bit string"),
        };
        spki.to_der().expect("encode SPKI")
    }

    /// One key spec per algorithm (LMS/HSS: H5, one and two levels).
    fn test_specs() -> [KeySpec; 5] {
        let h5 = LmsParams::from_height(5).expect("h5");
        [
            KeySpec::MlDsa44,
            KeySpec::MlDsa65,
            KeySpec::Ed25519,
            KeySpec::LmsHss {
                params: h5,
                levels: 1,
            },
            KeySpec::LmsHss {
                params: h5,
                levels: 2,
            },
        ]
    }

    /// The DER header of keelsign's LMS/HSS `SubjectPublicKeyInfo` (docs/keys.md):
    /// SEQUENCE, AlgorithmIdentifier { id-alg-hss-lms-hashsig }, BIT STRING { 0 unused
    /// bits, OCTET STRING (60) }, then the 60-byte HSS public key.
    const LMS_SPKI_HEADER: &str = "3050300d060b2a864886f70d0109100311033f00043c";

    #[test]
    fn lms_key_files_round_trip_and_spki_has_the_rfc_8708_header() {
        let h5 = LmsParams::from_height(5).expect("h5");
        for levels in [1u8, 2] {
            let (key, caches) =
                PrivateKey::generate_with_caches(KeySpec::LmsHss { params: h5, levels })
                    .expect("generate");
            let caches = caches.expect("LMS keys come with caches");
            assert_eq!(caches.bottom.is_some(), levels == 2);
            assert_eq!(key.algorithm(), KeyAlgorithm::LmsHss);
            let lms = key.as_lms().expect("lms");
            assert_eq!(lms.levels(), usize::from(levels));
            let raw = key.raw_public_key();
            assert_eq!(raw.len(), 60);
            assert_eq!(raw[..4], u32::from(levels).to_be_bytes());
            assert_eq!(raw[4..12], [0, 0, 0, 5, 0, 0, 0, 4]);
            // The public key is the root of the top tree.
            assert_eq!(raw[28..], caches.top.root());
            assert_eq!(
                key.identity(),
                KeyIdentity::KeyId(keelsign_verify::key_id_of(&raw))
            );
            assert_eq!(
                key.parameter_set(),
                if levels == 1 {
                    "LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8, L=1"
                } else {
                    "LMS_SHA256_M32_H5+LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8, L=2"
                }
            );

            let spki = key.public_key_spki_der().expect("spki");
            assert_eq!(spki.as_bytes().len(), 22 + 60);
            assert_eq!(hex(&spki.as_bytes()[..22]), LMS_SPKI_HEADER);
            assert_eq!(&spki.as_bytes()[22..], raw.as_slice());
            let public = PublicKey::from_bytes(spki.as_bytes()).expect("RFC 8708 SPKI");
            assert_eq!(public, PublicKey::LmsHss(raw.clone()));

            // PKCS#8: id-alg-hss-lms-hashsig, parameters absent, the blob as privateKey.
            let der = key.to_pkcs8_der().expect("der");
            let pki = PrivateKeyInfoRef::from_der(der.as_bytes()).expect("pki");
            assert_eq!(pki.algorithm.oid, ID_HSS_LMS_HASHSIG);
            assert!(pki.algorithm.parameters.is_none());
            assert_eq!(pki.private_key.as_bytes()[0], 1, "blob version 1");
            for (bytes, passphrase) in [
                (der.as_bytes().to_vec(), None),
                (key.to_pem().expect("pem").as_bytes().to_vec(), None),
                (
                    key.to_encrypted_der(b"pw")
                        .expect("enc")
                        .as_bytes()
                        .to_vec(),
                    Some(&b"pw"[..]),
                ),
            ] {
                let back = PrivateKey::from_bytes(&bytes, passphrase).expect("load");
                assert_eq!(back.raw_public_key(), raw);
                assert_eq!(back.to_pkcs8_der().expect("der").as_bytes(), der.as_bytes());
            }
        }
    }

    #[test]
    fn lms_key_files_with_bad_blobs_are_refused() {
        let h5 = LmsParams::from_height(5).expect("h5");
        let key = PrivateKey::generate(KeySpec::LmsHss {
            params: h5,
            levels: 1,
        })
        .expect("generate");
        let der = key.to_pkcs8_der().expect("der");
        let blob = PrivateKeyInfoRef::from_der(der.as_bytes())
            .expect("pki")
            .private_key
            .as_bytes()
            .to_vec();
        let file_with = |blob: &[u8]| {
            let algorithm = AlgorithmIdentifierRef {
                oid: ID_HSS_LMS_HASHSIG,
                parameters: None,
            };
            let pki = PrivateKeyInfoRef::new(algorithm, OctetStringRef::new(blob).expect("o"));
            SecretDocument::encode_msg(&pki).expect("encode")
        };
        let load = |blob: &[u8]| PrivateKey::from_bytes(file_with(blob).as_bytes(), None).err();
        assert!(load(&blob).is_none(), "the unmodified blob loads");
        let mut version = blob.clone();
        version[0] = 9;
        assert!(
            matches!(load(&version), Some(KeyFileError::Unsupported(r)) if r.contains("version 9"))
        );
        assert!(
            matches!(load(&blob[..blob.len() - 3]), Some(KeyFileError::Corrupt(r)) if r.contains("truncated"))
        );
        let mut typecode = blob.clone();
        typecode[8] = 0x0B; // LMS_SHA256_M24_H10: not signed by keelsign.
        assert!(matches!(load(&typecode), Some(KeyFileError::Unsupported(r)) if r.contains("0xb")));
        let mut ots = blob.clone();
        ots[12] = 0x03; // LMOTS_SHA256_N32_W4.
        assert!(matches!(load(&ots), Some(KeyFileError::Unsupported(_))));
        // The stored public key does not match the stored top tree (its typecode or I).
        let mut pub_type = blob.clone();
        let at = blob.len() - 60 + 7;
        pub_type[at] = 0x06;
        assert!(
            matches!(load(&pub_type), Some(KeyFileError::Corrupt(r)) if r.contains("do not match"))
        );
        let mut pub_id = blob.clone();
        pub_id[blob.len() - 60 + 12] ^= 0x01;
        assert!(
            matches!(load(&pub_id), Some(KeyFileError::Corrupt(r)) if r.contains("do not match"))
        );
        // A wrong root T[1] is not recomputed when loading (that is an H20 tree for an
        // H20 key); the key ID the state file is bound to and the self-check of every
        // signed image catch it (keelsign/tests/lms_sign.rs).
        let mut root = blob.clone();
        let last = root.len() - 1;
        root[last] ^= 0x01;
        let loaded = PrivateKey::from_bytes(file_with(&root).as_bytes(), None).expect("loads");
        assert_ne!(loaded.identity(), key.identity());
        // Parameters present.
        let null = AnyRef::from(pkcs8::der::asn1::Null);
        let pki = PrivateKeyInfoRef::new(
            AlgorithmIdentifierRef {
                oid: ID_HSS_LMS_HASHSIG,
                parameters: Some(null),
            },
            OctetStringRef::new(&blob).expect("o"),
        );
        let with_params = SecretDocument::encode_msg(&pki).expect("encode");
        assert!(matches!(
            PrivateKey::from_bytes(with_params.as_bytes(), None),
            Err(KeyFileError::Corrupt(r)) if r.contains("parameters")
        ));
    }

    fn lms_key() -> Vec<u8> {
        // L = 1, LMS_SHA256_M32_H5 (5), LMOTS_SHA256_N32_W8 (4), I (16 bytes), T[1] (32).
        let mut key = vec![0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 4];
        key.extend_from_slice(&[0x11; 16]);
        key.extend_from_slice(&[0x22; 32]);
        key
    }

    #[test]
    fn public_key_files_round_trip_through_pubkey_and_known_vectors() {
        // Every generated key: the PEM and DER `pubkey` output read back as the same raw
        // key and identity.
        for spec in test_specs() {
            let algorithm = spec.algorithm();
            let private = PrivateKey::generate(spec).expect("generate");
            let pem = private.public_key_spki_pem().expect("pem");
            let der = private.public_key_spki_der().expect("der");
            for bytes in [pem.as_bytes(), der.as_bytes()] {
                let public = PublicKey::from_bytes(bytes).expect("read SPKI");
                assert_eq!(public.algorithm_name(), algorithm.name());
                assert_eq!(public.raw(), private.raw_public_key());
                assert_eq!(public.identity(), private.identity());
                assert_eq!(
                    public.trusted_key().is_some(),
                    algorithm != KeyAlgorithm::Ed25519
                );
                assert_eq!(
                    public.ed25519_key().is_some(),
                    algorithm == KeyAlgorithm::Ed25519
                );
            }
            // A private key given as a public key is refused (PEM and DER).
            let refused = KeyFileError::Corrupt("it holds a private key, not a public key".into());
            let private_pem = private.to_pem().expect("pem");
            assert_eq!(
                PublicKey::from_bytes(private_pem.as_bytes()),
                Err(refused.clone())
            );
            let private_der = private.to_pkcs8_der().expect("der");
            assert_eq!(
                PublicKey::from_bytes(private_der.as_bytes()),
                Err(refused.clone())
            );
            let encrypted = private.to_encrypted_der(b"pw").expect("encrypt");
            assert_eq!(PublicKey::from_bytes(encrypted.as_bytes()), Err(refused));
        }

        // RFC 8410 §10.1.
        let public = PublicKey::from_bytes(RFC8410_PUBLIC_PEM.as_bytes()).expect("RFC 8410");
        assert_eq!(
            public.identity().to_string(),
            format!("keyhash: {RFC8410_KEYHASH}")
        );

        // RFC 9881 C.2, from the C.1 seed.
        for (i, algorithm) in [KeyAlgorithm::MlDsa44, KeyAlgorithm::MlDsa65]
            .into_iter()
            .enumerate()
        {
            let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
            let spki = PrivateKey::from_seed(algorithm, &seed)
                .expect("seed")
                .public_key_spki_der()
                .expect("spki");
            assert_eq!(
                hex(&keelsign_verify::key_id_of(spki.as_bytes())),
                RFC9881_SPKI_SHA256[i][..32]
            );
            let public = PublicKey::from_bytes(spki.as_bytes()).expect("RFC 9881");
            assert_eq!(
                public.identity().to_string(),
                format!("key id: {}", RFC9881_KEY_IDS[i])
            );
        }

        // RFC 8708: the BIT STRING holds the DER OCTET STRING of the HSS key.
        let key = lms_key();
        let wrapped = OctetStringRef::new(&key)
            .and_then(|o| o.to_der())
            .expect("octets");
        let der = spki_der(ID_HSS_LMS_HASHSIG, None, &wrapped);
        let public = PublicKey::from_bytes(&der).expect("RFC 8708");
        assert_eq!(public, PublicKey::LmsHss(key.clone()));
        assert_eq!(public.algorithm_name(), "lms-hss");
        assert_eq!(
            public.identity(),
            KeyIdentity::KeyId(keelsign_verify::key_id_of(&key))
        );
        let pem = Document::try_from(der.as_slice())
            .expect("doc")
            .to_pem(PEM_PUBLIC_KEY, LineEnding::LF)
            .expect("pem");
        assert_eq!(PublicKey::from_bytes(pem.as_bytes()), Ok(public));

        // Refusals: the raw key not wrapped, a bad typecode, parameters present, unknown
        // OID, wrong lengths, garbage.
        let corrupt = |bytes: &[u8]| match PublicKey::from_bytes(bytes) {
            Err(KeyFileError::Corrupt(reason)) => reason,
            other => panic!("expected Corrupt, got {other:?}"),
        };
        assert!(corrupt(&spki_der(ID_HSS_LMS_HASHSIG, None, &key)).contains("OCTET STRING"));
        let mut bad_type = key.clone();
        bad_type[7] = 0x7f;
        let bad_type = OctetStringRef::new(&bad_type)
            .and_then(|o| o.to_der())
            .expect("o");
        assert!(corrupt(&spki_der(ID_HSS_LMS_HASHSIG, None, &bad_type)).contains("HSS/LMS"));
        let null = AnyRef::from(pkcs8::der::asn1::Null);
        assert!(corrupt(&spki_der(ID_ED25519, Some(null), &[0; 32])).contains("parameters"));
        assert!(corrupt(&spki_der(ID_ED25519, None, &[0; 31])).contains("31 bytes"));
        assert!(corrupt(&spki_der(ID_ML_DSA_44, None, &[0; 1952])).contains("1,312"));
        assert!(corrupt(&spki_der(ID_ML_DSA_65, None, &[0; 1312])).contains("1,952"));
        assert!(corrupt(b"").contains("empty"));
        assert!(corrupt(b"\x30\x03garbage").contains("neither a PEM file nor a DER"));
        let unknown = ObjectIdentifier::new_unwrap("1.3.101.113");
        match PublicKey::from_bytes(&spki_der(unknown, None, &[0; 57])) {
            Err(KeyFileError::Unsupported(reason)) => {
                for oid in [ID_ML_DSA_44, ID_ML_DSA_65, ID_ED25519, ID_HSS_LMS_HASHSIG] {
                    assert!(reason.contains(&oid.to_string()), "{reason}");
                }
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        match PublicKey::from_bytes(
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        ) {
            Err(KeyFileError::Unsupported(reason)) => assert!(reason.contains("CERTIFICATE")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex(&[]), "");
        assert_eq!(
            KeyIdentity::KeyId([0xab; 16]).to_string(),
            format!("key id: {}", "ab".repeat(16))
        );
        assert_eq!(
            KeyIdentity::KeyHash([0xcd; 32]).to_string(),
            format!("keyhash: {}", "cd".repeat(32))
        );
    }
}
