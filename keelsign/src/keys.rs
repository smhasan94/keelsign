//! Key generation and key file encodings (see `docs/keys.md`).
//!
//! - Private keys: PKCS#8 v1 `PrivateKeyInfo` (RFC 5208 / RFC 5958), PEM label
//!   `PRIVATE KEY` or DER. ML-DSA keys use the RFC 9881 §6 `seed` form; Ed25519 keys the
//!   RFC 8410 §7 v1 layout (no public key), which imgtool reads.
//! - Encrypted private keys: PKCS#8 `EncryptedPrivateKeyInfo`, PBES2 with scrypt
//!   (N = 2^14, r = 8, p = 1, 16-byte salt) and AES-256-CBC, PEM label
//!   `ENCRYPTED PRIVATE KEY` or DER.
//! - Public keys: `SubjectPublicKeyInfo` (RFC 5280), PEM label `PUBLIC KEY` or DER.

use crate::error::{Error, KeyFileError};
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
}

impl KeyAlgorithm {
    /// All algorithms, in CLI order.
    pub const ALL: [Self; 3] = [Self::MlDsa44, Self::MlDsa65, Self::Ed25519];

    /// The CLI name: `ml-dsa-44`, `ml-dsa-65` or `ed25519`.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::Ed25519 => "ed25519",
        }
    }

    /// The algorithm OID used in the key files.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::MlDsa44 => ID_ML_DSA_44,
            Self::MlDsa65 => ID_ML_DSA_65,
            Self::Ed25519 => ID_ED25519,
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
}

fn encode_err(e: impl fmt::Display) -> Error {
    Error::Encode(e.to_string())
}

impl PrivateKey {
    /// Generate a new key from 32 bytes of operating-system randomness (the ML-DSA seed
    /// ξ, or the Ed25519 secret key).
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self::from_seed(algorithm, &seed))
    }

    /// The key derived from a 32-byte seed (ML-DSA ξ or the Ed25519 secret key).
    fn from_seed(algorithm: KeyAlgorithm, seed: &[u8; 32]) -> Self {
        match algorithm {
            KeyAlgorithm::MlDsa44 => {
                Self::MlDsa44(Box::new(ml_dsa::SigningKey::from_seed(&(*seed).into())))
            }
            KeyAlgorithm::MlDsa65 => {
                Self::MlDsa65(Box::new(ml_dsa::SigningKey::from_seed(&(*seed).into())))
            }
            KeyAlgorithm::Ed25519 => {
                Self::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed)))
            }
        }
    }

    /// The key's algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::MlDsa44(_) => KeyAlgorithm::MlDsa44,
            Self::MlDsa65(_) => KeyAlgorithm::MlDsa65,
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
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

    /// The DER `SubjectPublicKeyInfo` of the public key.
    pub fn public_key_spki_der(&self) -> Result<Document, Error> {
        match self {
            Self::MlDsa44(k) => k.verifying_key().to_public_key_der(),
            Self::MlDsa65(k) => k.verifying_key().to_public_key_der(),
            Self::Ed25519(k) => k.verifying_key().to_public_key_der(),
        }
        .map_err(encode_err)
    }

    /// The PEM `SubjectPublicKeyInfo` (label `PUBLIC KEY`, LF line endings).
    pub fn public_key_spki_pem(&self) -> Result<String, Error> {
        self.public_key_spki_der()?
            .to_pem(PEM_PUBLIC_KEY, LineEnding::LF)
            .map_err(encode_err)
    }

    /// The raw public key: the FIPS 204 encoding (1,312 / 1,952 bytes) or the 32-byte
    /// Ed25519 key.
    pub fn raw_public_key(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(k) => k.verifying_key().encode().to_vec(),
            Self::MlDsa65(k) => k.verifying_key().encode().to_vec(),
            Self::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
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
                     {ID_ML_DSA_44}, ML-DSA-65 {ID_ML_DSA_65} and Ed25519 {ID_ED25519})"
                ))
            })?;
        if pki.algorithm.parameters.is_some() {
            return Err(KeyFileError::Corrupt(format!(
                "{algorithm} AlgorithmIdentifier has parameters; they must be absent \
                 (RFC 9881 §2, RFC 8410 §3)"
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
        if u32::from(r).checked_mul(u32::from(p)).is_none() {
            return Err(out_of_range(format!("scrypt r * p = {r} * {p}")));
        }
    } else if let Some(pbkdf2) = kdf.pbkdf2() {
        let i = pbkdf2.iteration_count;
        if !(1..=MAX_PBKDF2_ITERATIONS).contains(&i) {
            return Err(out_of_range(format!(
                "PBKDF2 iteration count {i} (1 to 10,000,000)"
            )));
        }
    } else {
        return Err(KeyFileError::Unsupported(UNSUPPORTED_SCHEME.into()));
    }
    Ok(())
}

fn public_key_given() -> KeyFileError {
    KeyFileError::Corrupt("it holds a public key, not a private key".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
