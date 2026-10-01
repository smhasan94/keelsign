//! Errors of the `keelsign` CLI and their process exit codes.
//!
//! | Exit code | Meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | I/O, random-number generator or internal error |
//! | 2 | usage error (bad arguments, empty passphrase) |
//! | 3 | output file exists and `--force` was not given |
//! | 4 | passphrase problem: wrong, missing, or given for an unencrypted key |
//! | 5 | corrupt or unsupported key file |
//! | 6 | the key file holds a different algorithm than `--alg` asks for |

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
            Self::Io { .. } | Self::Rng(_) | Self::Encode(_) => 1,
            Self::Usage(_) => 2,
            Self::Exists(_) => 3,
            Self::KeyFile { error, .. } => match error {
                KeyFileError::PassphraseRequired
                | KeyFileError::PassphraseUnexpected
                | KeyFileError::WrongPassphrase => 4,
                KeyFileError::Corrupt(_) | KeyFileError::Unsupported(_) => 5,
            },
            Self::AlgorithmMismatch { .. } => 6,
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
        ];
        for (error, code) in &cases {
            assert_eq!(error.exit_code(), *code, "{error}");
            assert_ne!(error.exit_code(), 0, "{error}");
        }
        // Every exit code 1..=6 is used, and the classes do not overlap.
        let mut codes: Vec<u8> = cases.iter().map(|(e, _)| e.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6]);

        let mismatch = Error::AlgorithmMismatch {
            path: path(),
            found: KeyAlgorithm::MlDsa44,
            requested: KeyAlgorithm::Ed25519,
        }
        .to_string();
        assert!(mismatch.contains("ml-dsa-44") && mismatch.contains("ed25519"));
        assert!(Error::Exists(path()).to_string().contains("--force"));
        assert!(
            Error::key_file(path(), KeyFileError::WrongPassphrase)
                .to_string()
                .contains("wrong passphrase for key.pem")
        );
    }
}
