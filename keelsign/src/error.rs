//! Errors of the `keelsign` CLI and their process exit codes.
//!
//! | Exit code | Meaning |
//! |---|---|
//! | 0 | success; for `verify`, the image is verified under the policy |
//! | 1 | I/O error (a missing or unreadable image, key or `--pub` file), random-number generator or internal error |
//! | 2 | usage error (bad arguments, empty passphrase; for `verify`: no `--pub`, more than 8 `--pub` keys of a kind, the same key twice, a `--policy` that needs a kind of key no `--pub` gives) |
//! | 3 | output file exists and `--force` was not given |
//! | 4 | passphrase problem: wrong, missing, or given for an unencrypted key |
//! | 5 | corrupt or unsupported key file, private or public (a `--pub` file that is not a supported `SubjectPublicKeyInfo`, or is a private key) |
//! | 6 | the key file holds a different algorithm than `--alg` asks for (or, for `sign`, `--key` is not ML-DSA / `--hybrid-key` is not Ed25519) |
//! | 7 | the input image is rejected as malformed: not an MCUboot image or too large (`verify`, `inspect`, `sign`); for `sign` also an image rule broken or bytes after its TLV area |
//! | 8 | the input image already carries keelsign TLVs (or, with `--hybrid-key`, an Ed25519 pair) and `--replace` was not given |
//! | 9 | `verify`: the image is not verified under the policy (a signature invalid or malformed, a key not trusted, a TLV missing or repeated, the Ed25519 half rejected, an image rule broken, an unsupported parameter set) |
//!
//! The table is final (docs/verify.md has the full one).

use crate::keys::KeyAlgorithm;
use std::fmt;
use std::path::PathBuf;

/// Why a key file could not be loaded. Carries no path; [`Error::KeyFile`] adds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileError {
    /// The key is encrypted and no passphrase was given.
    PassphraseRequired,
    /// A passphrase was given but the key is not encrypted.
    PassphraseUnexpected,
    /// Decryption failed: the passphrase is wrong (AES-CBC cannot tell this apart from a
    /// corrupt ciphertext).
    WrongPassphrase,
    /// The file is not a well-formed key file of a supported kind.
    Corrupt(String),
    /// The file is well formed but holds something keelsign does not read.
    Unsupported(String),
}

/// Why the state of an LMS/HSS key refuses a signature. Carries no path;
/// [`Error::LmsState`] adds the state file or journal it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmsStateError {
    /// The state file or the journal is missing.
    Missing,
    /// The state file belongs to another key.
    ForeignKey {
        /// The key ID of the key being used.
        expected: String,
        /// The key ID the state file is bound to.
        found: String,
    },
    /// The state file is behind the journal: it was restored from a copy.
    BehindJournal {
        /// The next leaf the state file names.
        next: u64,
        /// The highest leaf the journal records as used.
        used: u64,
    },
    /// The state file or journal is malformed or does not fit the key.
    Corrupt(String),
    /// Another keelsign process holds the key's lock.
    Locked,
}

/// A `keelsign` CLI error. [`Error::exit_code`] gives the process exit code.
#[derive(Debug)]
pub enum Error {
    /// An I/O operation failed. `what` names the operation and the path.
    Io {
        /// The operation and path, for example `write key.pem`.
        what: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The operating system's random-number generator failed.
    Rng(String),
    /// Encoding a key failed (an internal error).
    Encode(String),
    /// A usage error the argument parser cannot catch, such as an empty passphrase.
    Usage(String),
    /// The output file exists and `--force` was not given.
    Exists(PathBuf),
    /// A key file could not be loaded.
    KeyFile {
        /// The key file.
        path: PathBuf,
        /// Why it could not be loaded.
        error: KeyFileError,
    },
    /// An internal error, such as a signed image that does not verify.
    Internal(String),
    /// The input image is rejected (not an MCUboot image, an image rule, trailing bytes,
    /// too large).
    Image {
        /// The image file.
        path: PathBuf,
        /// Why it is rejected.
        reason: String,
    },
    /// The input image already carries signatures `sign` would add, and `--replace` was
    /// not given.
    AlreadySigned {
        /// The image file.
        path: PathBuf,
        /// What it already carries, for example `keelsign TLVs`.
        what: &'static str,
    },
    /// `verify`: the image is well formed but not verified under the policy.
    NotVerified {
        /// The image file.
        path: PathBuf,
        /// The policy it was checked under.
        policy: keelsign_verify::Policy,
        /// Why the verifier refused it.
        source: keelsign_verify::Error,
    },
    /// A key of the wrong kind for its option (`sign --key` must be ML-DSA,
    /// `--hybrid-key` Ed25519).
    WrongKeyKind {
        /// The key file.
        path: PathBuf,
        /// The option, `--key` or `--hybrid-key`.
        option: &'static str,
        /// The algorithm of the key in the file.
        found: KeyAlgorithm,
        /// What the option needs, for example `ML-DSA-44 or ML-DSA-65`.
        expected: &'static str,
    },
    /// The state of an LMS/HSS key refuses a signature (missing, another key's, rolled
    /// back, corrupt or locked).
    LmsState {
        /// The state file or journal.
        path: PathBuf,
        /// Why it refuses.
        reason: LmsStateError,
    },
    /// Every leaf of an LMS/HSS key is used.
    LeafIndexExhausted {
        /// The key file.
        key: PathBuf,
        /// How many signatures the key could make.
        leaves: u64,
    },
    /// The key file holds a different algorithm than `--alg` asks for.
    AlgorithmMismatch {
        /// The key file.
        path: PathBuf,
        /// The algorithm of the key in the file.
        found: KeyAlgorithm,
        /// The algorithm given with `--alg`.
        requested: KeyAlgorithm,
    },
}

impl Error {
    /// The process exit code for this error (see the module documentation).
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Io { .. } | Self::Rng(_) | Self::Encode(_) | Self::Internal(_) => 1,
            Self::Usage(_) => 2,
            Self::Exists(_) => 3,
            Self::KeyFile { error, .. } => match error {
                KeyFileError::PassphraseRequired
                | KeyFileError::PassphraseUnexpected
                | KeyFileError::WrongPassphrase => 4,
                KeyFileError::Corrupt(_) | KeyFileError::Unsupported(_) => 5,
            },
            Self::AlgorithmMismatch { .. } | Self::WrongKeyKind { .. } => 6,
            Self::Image { .. } => 7,
            Self::AlreadySigned { .. } => 8,
            Self::NotVerified { .. } => 9,
            Self::LmsState { .. } => 10,
            Self::LeafIndexExhausted { .. } => 11,
        }
    }

    /// An [`Error::KeyFile`] for `path`.
    pub fn key_file(path: impl Into<PathBuf>, error: KeyFileError) -> Self {
        Self::KeyFile {
            path: path.into(),
            error,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { what, source } => write!(f, "{what}: {source}"),
            Self::Rng(e) => write!(
                f,
                "the operating system random-number generator failed: {e}"
            ),
            Self::Encode(e) => write!(f, "internal error: could not encode the key: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
            Self::Image { path, reason } => write!(f, "{}: {reason}", path.display()),
            Self::AlreadySigned { path, what } => write!(
                f,
                "{} already carries {what}; give --replace to replace them",
                path.display()
            ),
            Self::WrongKeyKind {
                path,
                option,
                found,
                expected,
            } => write!(
                f,
                "{option} {} holds an {} key; {option} needs {expected}",
                path.display(),
                found.name()
            ),
            Self::NotVerified {
                path,
                policy,
                source,
            } => write!(
                f,
                "{}: not verified under policy {}: {source}",
                path.display(),
                crate::verify::policy_name(*policy)
            ),
            Self::Usage(msg) => f.write_str(msg),
            Self::Exists(path) => {
                write!(f, "refusing to overwrite {} (use --force)", path.display())
            }
            Self::KeyFile { path, error } => {
                let path = path.display();
                match error {
                    KeyFileError::PassphraseRequired => write!(
                        f,
                        "{path} is encrypted; give its passphrase with --passphrase-file or \
                         --passphrase-env"
                    ),
                    KeyFileError::PassphraseUnexpected => write!(
                        f,
                        "{path} is not encrypted, but a passphrase was given; drop \
                         --passphrase-file / --passphrase-env"
                    ),
                    KeyFileError::WrongPassphrase => write!(
                        f,
                        "wrong passphrase for {path} (or the encrypted key is corrupt)"
                    ),
                    KeyFileError::Corrupt(reason) => {
                        write!(f, "{path}: corrupt or invalid key file: {reason}")
                    }
                    KeyFileError::Unsupported(reason) => {
                        write!(f, "{path}: unsupported key file: {reason}")
                    }
                }
            }
            Self::LmsState { path, reason } => {
                let path = path.display();
                match reason {
                    LmsStateError::Missing => write!(
                        f,
                        "{path} is missing: an LMS/HSS key signs only with its state file and \
                         journal (docs/keys.md#stateful-lms-keys); if this key has signed \
                         before, retire it rather than recreate them"
                    ),
                    LmsStateError::ForeignKey { expected, found } => write!(
                        f,
                        "{path} belongs to another key (key id {found}; this key is \
                         {expected})"
                    ),
                    LmsStateError::BehindJournal { next, used } => write!(
                        f,
                        "{path} says the next leaf is {next}, but the journal records leaf \
                         {used} as used: the state file was restored from a copy; do not \
                         sign, retire this key"
                    ),
                    LmsStateError::Corrupt(reason) => {
                        write!(f, "{path}: corrupt LMS/HSS state: {reason}")
                    }
                    LmsStateError::Locked => write!(
                        f,
                        "{path} is locked by another keelsign process signing with this key"
                    ),
                }
            }
            Self::LeafIndexExhausted { key, leaves } => write!(
                f,
                "LeafIndexExhausted: all {leaves} leaves of {} are used; generate a new key",
                key.display()
            ),
            Self::AlgorithmMismatch {
                path,
                found,
                requested,
            } => write!(
                f,
                "{} holds an {} key, but --alg {} was given",
                path.display(),
                found.name(),
                requested.name()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::NotVerified { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_per_kind() {
        let path = || PathBuf::from("key.pem");
        let cases: Vec<(Error, u8)> = vec![
            (
                Error::Io {
                    what: "read key.pem".into(),
                    source: std::io::Error::other("boom"),
                },
                1,
            ),
            (Error::Rng("no entropy".into()), 1),
            (Error::Encode("too long".into()), 1),
            (
                Error::Internal("the signed image does not verify".into()),
                1,
            ),
            (Error::Usage("empty passphrase".into()), 2),
            (Error::Exists(path()), 3),
            (Error::key_file(path(), KeyFileError::PassphraseRequired), 4),
            (
                Error::key_file(path(), KeyFileError::PassphraseUnexpected),
                4,
            ),
            (Error::key_file(path(), KeyFileError::WrongPassphrase), 4),
            (
                Error::key_file(path(), KeyFileError::Corrupt("x".into())),
                5,
            ),
            (
                Error::key_file(path(), KeyFileError::Unsupported("x".into())),
                5,
            ),
            (
                Error::AlgorithmMismatch {
                    path: path(),
                    found: KeyAlgorithm::MlDsa44,
                    requested: KeyAlgorithm::MlDsa65,
                },
                6,
            ),
            (
                Error::WrongKeyKind {
                    path: path(),
                    option: "--key",
                    found: KeyAlgorithm::Ed25519,
                    expected: "ML-DSA-44 or ML-DSA-65",
                },
                6,
            ),
            (
                Error::Image {
                    path: path(),
                    reason: "not an MCUboot image".into(),
                },
                7,
            ),
            (
                Error::AlreadySigned {
                    path: path(),
                    what: "keelsign TLVs",
                },
                8,
            ),
            (
                Error::NotVerified {
                    path: path(),
                    policy: keelsign_verify::Policy::Hybrid,
                    source: keelsign_verify::Error::KeyNotTrusted,
                },
                9,
            ),
        ];
        for (error, code) in &cases {
            assert_eq!(error.exit_code(), *code, "{error}");
            assert_ne!(error.exit_code(), 0, "{error}");
        }
        // Every exit code 1..=9 is used, and the classes do not overlap.
        let mut codes: Vec<u8> = cases.iter().map(|(e, _)| e.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let mismatch = Error::AlgorithmMismatch {
            path: path(),
            found: KeyAlgorithm::MlDsa44,
            requested: KeyAlgorithm::Ed25519,
        }
        .to_string();
        assert!(mismatch.contains("ml-dsa-44") && mismatch.contains("ed25519"));
        assert!(Error::Exists(path()).to_string().contains("--force"));
        assert!(
            Error::AlreadySigned {
                path: path(),
                what: "keelsign TLVs",
            }
            .to_string()
            .contains("--replace")
        );
        assert_eq!(
            Error::NotVerified {
                path: PathBuf::from("app.bin"),
                policy: keelsign_verify::Policy::PqOnly,
                source: keelsign_verify::Error::KeyNotTrusted,
            }
            .to_string(),
            "app.bin: not verified under policy pq: post-quantum key ID is not in the trusted \
             key set"
        );
        assert!(
            Error::key_file(path(), KeyFileError::WrongPassphrase)
                .to_string()
                .contains("wrong passphrase for key.pem")
        );
    }
}
