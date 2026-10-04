//! Command-line interface: `keelsign keygen`, `pubkey`, `sign` and `inspect`.

use crate::error::Error;
use crate::keyfile;
use crate::keys::{KeyAlgorithm, PrivateKey};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{self, Write};
use std::path::PathBuf;

/// keelsign: post-quantum firmware signing kit (pre-release).
#[derive(Debug, Parser)]
#[command(name = "keelsign", version, about, long_about = None)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// A `keelsign` command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a private key file (PKCS#8, mode 0600).
    Keygen(KeygenArgs),
    /// Export the public key of a private key file (SubjectPublicKeyInfo).
    Pubkey(PubkeyArgs),
    /// Add an ML-DSA signature (optionally with an Ed25519 pair) to an MCUboot image.
    Sign(SignArgs),
    /// Describe an MCUboot image: header, TLVs, digest, key IDs and signatures.
    Inspect(InspectArgs),
}

/// Arguments of `keelsign inspect`.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Write JSON (docs/inspect-schema.json) instead of text.
    #[arg(long)]
    pub json: bool,
    /// The MCUboot image (bytes after its TLV area are reported, not parsed).
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
}

/// Arguments of `keelsign sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// ML-DSA-44 or ML-DSA-65 private key file (PKCS#8 PEM or DER, encrypted or not).
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,
    /// Ed25519 private key file: also add MCUboot's KEYHASH + ED25519 pair (hybrid image).
    #[arg(long, value_name = "FILE")]
    pub hybrid_key: Option<PathBuf>,
    /// Replace existing keelsign TLVs (and, with --hybrid-key, an existing Ed25519 pair).
    #[arg(long)]
    pub replace: bool,
    /// Replace OUT if it exists.
    #[arg(long)]
    pub force: bool,
    /// Passphrase of whichever of --key / --hybrid-key is encrypted.
    #[command(flatten)]
    pub passphrase: PassphraseArgs,
    /// The MCUboot image to sign (not padded; no bytes after its TLV area).
    #[arg(value_name = "IN")]
    pub input: PathBuf,
    /// The signed image to create.
    #[arg(value_name = "OUT")]
    pub output: PathBuf,
}

/// Arguments of `keelsign keygen`.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Signature algorithm of the new key.
    #[arg(long, value_enum)]
    pub alg: AlgArg,
    /// Private key file to create.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// File encoding.
    #[arg(long, value_enum, default_value_t = FormatArg::Pem)]
    pub format: FormatArg,
    /// Encrypt the key with a passphrase.
    #[command(flatten)]
    pub passphrase: PassphraseArgs,
    /// Replace FILE if it exists.
    #[arg(long)]
    pub force: bool,
}

/// Arguments of `keelsign pubkey`.
#[derive(Debug, Args)]
pub struct PubkeyArgs {
    /// Private key file (PKCS#8 PEM or DER, encrypted or not).
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,
    /// Fail unless the key is of this algorithm.
    #[arg(long, value_enum)]
    pub alg: Option<AlgArg>,
    /// Public key file to create; without it the PEM is written to standard output.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// File encoding (`der` needs `--out`).
    #[arg(long, value_enum, default_value_t = FormatArg::Pem)]
    pub format: FormatArg,
    /// Passphrase of an encrypted key.
    #[command(flatten)]
    pub passphrase: PassphraseArgs,
    /// Replace the --out file if it exists.
    #[arg(long)]
    pub force: bool,
}

/// Where the passphrase comes from (at most one source).
#[derive(Debug, Args)]
#[group(required = false, multiple = false)]
pub struct PassphraseArgs {
    /// Read the passphrase from the first line of PATH.
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
    /// Read the passphrase from the environment variable VAR.
    #[arg(long, value_name = "VAR")]
    pub passphrase_env: Option<String>,
}

/// `--alg` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgArg {
    /// ML-DSA-44 (FIPS 204).
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    /// Ed25519 (RFC 8032), for hybrid images.
    #[value(name = "ed25519")]
    Ed25519,
}

impl From<AlgArg> for KeyAlgorithm {
    fn from(alg: AlgArg) -> Self {
        match alg {
            AlgArg::MlDsa44 => Self::MlDsa44,
            AlgArg::MlDsa65 => Self::MlDsa65,
            AlgArg::Ed25519 => Self::Ed25519,
        }
    }
}

/// `--format` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    /// PEM text.
    Pem,
    /// Binary DER.
    Der,
}

fn out_error(source: io::Error) -> Error {
    Error::Io {
        what: "write output".into(),
        source,
    }
}

/// Run a parsed command line.
pub fn run(cli: &Cli) -> Result<(), Error> {
    match &cli.command {
        Command::Keygen(args) => keygen(args),
        Command::Pubkey(args) => pubkey(args),
        Command::Sign(args) => sign(args),
        Command::Inspect(args) => inspect(args),
    }
}

fn inspect(args: &InspectArgs) -> Result<(), Error> {
    let bytes = crate::image_file::read_image(&args.image)?;
    let image = crate::image_file::parse(&args.image, &bytes)?;
    let digest = crate::image_file::digest(&bytes, &image)?;
    let report = crate::inspect::to_json(&bytes, &image, &digest);
    let text = if args.json {
        let mut text = serde_json::to_string_pretty(&report)
            .map_err(|e| Error::Internal(format!("could not write JSON: {e}")))?;
        text.push('\n');
        text
    } else {
        crate::inspect::to_human(&report)
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes()).map_err(out_error)?;
    stdout.flush().map_err(out_error)
}

fn sign(args: &SignArgs) -> Result<(), Error> {
    let request = crate::sign::SignRequest {
        input: args.input.clone(),
        output: args.output.clone(),
        key: args.key.clone(),
        hybrid_key: args.hybrid_key.clone(),
        replace: args.replace,
        force: args.force,
    };
    let passphrase = keyfile::read_passphrase(&args.passphrase)?;
    let report = crate::sign::run(&request, passphrase.as_ref())?;
    let mut stdout = io::stdout().lock();
    for line in report.lines(&args.output) {
        writeln!(stdout, "{line}").map_err(out_error)?;
    }
    Ok(())
}

fn keygen(args: &KeygenArgs) -> Result<(), Error> {
    keyfile::ensure_absent(&args.out, args.force)?;
    let passphrase = keyfile::read_passphrase(&args.passphrase)?;
    let key = PrivateKey::generate(args.alg.into())?;
    let encoded: zeroize::Zeroizing<Vec<u8>> = match (args.format, &passphrase) {
        (FormatArg::Pem, None) => zeroize::Zeroizing::new(key.to_pem()?.as_bytes().to_vec()),
        (FormatArg::Pem, Some(pw)) => {
            zeroize::Zeroizing::new(key.to_encrypted_pem(pw)?.as_bytes().to_vec())
        }
        (FormatArg::Der, None) => key.to_pkcs8_der()?.to_bytes(),
        (FormatArg::Der, Some(pw)) => key.to_encrypted_der(pw)?.to_bytes(),
    };
    keyfile::write_private(&args.out, &encoded, args.force)?;

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "algorithm: {}", key.algorithm()).map_err(out_error)?;
    writeln!(stdout, "{}", key.identity()).map_err(out_error)?;
    writeln!(
        stdout,
        "private key: {} (PKCS#8 {}, {})",
        args.out.display(),
        match args.format {
            FormatArg::Pem => "PEM",
            FormatArg::Der => "DER",
        },
        if passphrase.is_some() {
            "encrypted"
        } else {
            "not encrypted"
        }
    )
    .map_err(out_error)?;
    #[cfg(not(unix))]
    writeln!(
        io::stderr().lock(),
        "note: file permissions of {} are not restricted on this platform; protect it \
         yourself",
        args.out.display()
    )
    .map_err(out_error)?;
    Ok(())
}

fn pubkey(args: &PubkeyArgs) -> Result<(), Error> {
    if args.format == FormatArg::Der && args.out.is_none() {
        return Err(Error::Usage(
            "--format der needs --out (DER is binary and is not written to standard output)".into(),
        ));
    }
    if let Some(out) = &args.out {
        keyfile::ensure_not_same_file(&args.key, out)?;
        keyfile::ensure_absent(out, args.force)?;
    }
    let passphrase = keyfile::read_passphrase(&args.passphrase)?;
    let bytes = keyfile::read_key_file(&args.key)?;
    let key = PrivateKey::from_bytes(&bytes, passphrase.as_ref().map(|p| p.as_slice()))
        .map_err(|e| Error::key_file(&args.key, e))?;
    if let Some(requested) = args.alg.map(KeyAlgorithm::from)
        && requested != key.algorithm()
    {
        return Err(Error::AlgorithmMismatch {
            path: args.key.clone(),
            found: key.algorithm(),
            requested,
        });
    }

    let public = match args.format {
        FormatArg::Pem => key.public_key_spki_pem()?.into_bytes(),
        FormatArg::Der => key.public_key_spki_der()?.into_vec(),
    };
    match &args.out {
        Some(out) => keyfile::write_public(out, &public, args.force)?,
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&public).map_err(out_error)?;
            stdout.flush().map_err(out_error)?;
        }
    }

    let mut stderr = io::stderr().lock();
    writeln!(stderr, "algorithm: {}", key.algorithm()).map_err(out_error)?;
    writeln!(stderr, "{}", key.identity()).map_err(out_error)?;
    Ok(())
}
