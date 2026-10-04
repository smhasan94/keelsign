//! Command-line interface: `keelsign keygen`, `pubkey`, `sign`, `inspect` and `verify`.

use crate::error::Error;
use crate::keyfile;
use crate::keys::{KeyAlgorithm, KeySpec, PrivateKey};
use crate::lms_sign::LmsParams;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
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
    /// Generate a private key file (PKCS#8, mode 0600); for LMS/HSS also its state file
    /// and journal.
    Keygen(KeygenArgs),
    /// Export the public key of a private key file (SubjectPublicKeyInfo).
    Pubkey(PubkeyArgs),
    /// Add an ML-DSA signature (optionally with an Ed25519 pair) to an MCUboot image.
    Sign(SignArgs),
    /// Describe an MCUboot image: header, TLVs, digest, key IDs and signatures.
    Inspect(InspectArgs),
    /// Verify an MCUboot image against trusted public keys under a policy, as the device
    /// does.
    Verify(VerifyArgs),
}

/// Arguments of `keelsign verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Trusted public key file (SubjectPublicKeyInfo PEM or DER: ML-DSA-44, ML-DSA-65,
    /// Ed25519 or HSS/LMS). Repeat for several keys: up to 8 post-quantum and 8 Ed25519.
    #[arg(long = "pub", value_name = "FILE", required = true, action = ArgAction::Append)]
    pub pubs: Vec<PathBuf>,
    /// Which signatures to require; without it, inferred from the keys (post-quantum
    /// keys only: pq; Ed25519 keys only: classical; both: hybrid).
    #[arg(long, value_enum)]
    pub policy: Option<PolicyArg>,
    /// Verify LMS/HSS under the strict CNSA 2.0 parameter policy: single-tree LMS only;
    /// ML-DSA and multi-level HSS signatures are refused.
    #[arg(long = "cnsa-2.0")]
    pub cnsa_2_0: bool,
    /// The MCUboot image (bytes after its TLV area, such as padding, are ignored).
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
}

/// `--policy` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyArg {
    /// The Ed25519 half only (MCUboot's KEYHASH + ED25519 pair).
    Classical,
    /// The post-quantum half only (keelsign key ID + PQ signature).
    Pq,
    /// Both halves.
    Hybrid,
}

impl From<PolicyArg> for keelsign_verify::Policy {
    fn from(policy: PolicyArg) -> Self {
        match policy {
            PolicyArg::Classical => Self::ClassicalOnly,
            PolicyArg::Pq => Self::PqOnly,
            PolicyArg::Hybrid => Self::Hybrid,
        }
    }
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
    /// Signature algorithm of the new key. The LMS/HSS keys (LMS_SHA256_M32_H10/H15/H20
    /// with LMOTS_SHA256_N32_W8) are stateful: see docs/keys.md.
    #[arg(long, value_enum)]
    pub alg: AlgArg,
    /// HSS levels of an LMS/HSS key: 1 (a single LMS tree, CNSA 2.0) or 2 (2^(2h)
    /// signatures; outside CNSA 2.0). Default 1.
    #[arg(long, value_name = "L", value_parser = clap::value_parser!(u8).range(1..=2))]
    pub hss_levels: Option<u8>,
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
    /// LMS/HSS, LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W8: 1,024 signatures per level
    /// (stateful).
    #[value(name = "lms-sha256-m32-h10")]
    LmsSha256M32H10,
    /// LMS/HSS, LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W8: 32,768 signatures per level
    /// (stateful).
    #[value(name = "lms-sha256-m32-h15")]
    LmsSha256M32H15,
    /// LMS/HSS, LMS_SHA256_M32_H20 / LMOTS_SHA256_N32_W8: 1,048,576 signatures per level
    /// (stateful; key generation takes minutes).
    #[value(name = "lms-sha256-m32-h20")]
    LmsSha256M32H20,
}

impl AlgArg {
    /// The LMS parameter set of an LMS/HSS value.
    pub fn lms_params(self) -> Option<LmsParams> {
        match self {
            Self::LmsSha256M32H10 => LmsParams::from_height(10),
            Self::LmsSha256M32H15 => LmsParams::from_height(15),
            Self::LmsSha256M32H20 => LmsParams::from_height(20),
            Self::MlDsa44 | Self::MlDsa65 | Self::Ed25519 => None,
        }
    }

    /// The key `keygen --alg self --hss-levels levels` generates.
    pub fn key_spec(self, levels: Option<u8>) -> Result<KeySpec, Error> {
        let spec = match self {
            Self::MlDsa44 => KeySpec::MlDsa44,
            Self::MlDsa65 => KeySpec::MlDsa65,
            Self::Ed25519 => KeySpec::Ed25519,
            Self::LmsSha256M32H10 | Self::LmsSha256M32H15 | Self::LmsSha256M32H20 => {
                let params = self
                    .lms_params()
                    .ok_or_else(|| Error::Internal("no LMS parameter set".into()))?;
                return Ok(KeySpec::LmsHss {
                    params,
                    levels: levels.unwrap_or(1),
                });
            }
        };
        if levels.is_some() {
            return Err(Error::Usage(format!(
                "--hss-levels applies to LMS/HSS keys only, not --alg {}",
                spec.algorithm()
            )));
        }
        Ok(spec)
    }
}

impl From<AlgArg> for KeyAlgorithm {
    fn from(alg: AlgArg) -> Self {
        match alg {
            AlgArg::MlDsa44 => Self::MlDsa44,
            AlgArg::MlDsa65 => Self::MlDsa65,
            AlgArg::Ed25519 => Self::Ed25519,
            AlgArg::LmsSha256M32H10 | AlgArg::LmsSha256M32H15 | AlgArg::LmsSha256M32H20 => {
                Self::LmsHss
            }
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
        Command::Verify(args) => verify(args),
    }
}

fn verify(args: &VerifyArgs) -> Result<(), Error> {
    let request = crate::verify::VerifyRequest {
        image: args.image.clone(),
        pubs: args.pubs.clone(),
        policy: args.policy,
        cnsa_2_0: args.cnsa_2_0,
    };
    let report = crate::verify::run(&request)?;
    let mut stdout = io::stdout().lock();
    for line in report.lines() {
        writeln!(stdout, "{line}").map_err(out_error)?;
    }
    stdout.flush().map_err(out_error)
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
    let spec = args.alg.key_spec(args.hss_levels)?;
    keyfile::ensure_absent(&args.out, args.force)?;
    if matches!(spec, KeySpec::LmsHss { .. }) {
        // The state file and journal are written after the key; refuse up front.
        keyfile::ensure_absent(&crate::lms_state::state_path(&args.out), args.force)?;
        keyfile::ensure_absent(&crate::lms_state::journal_path(&args.out), args.force)?;
    }
    let passphrase = keyfile::read_passphrase(&args.passphrase)?;
    if let KeySpec::LmsHss { params, levels } = spec
        && params.height() >= 20
    {
        writeln!(
            io::stderr().lock(),
            "note: computing {levels} LMS tree(s) of 2^{} leaves; this takes minutes",
            params.height()
        )
        .map_err(out_error)?;
    }
    let (key, caches) = PrivateKey::generate_with_caches(spec)?;
    let encoded: zeroize::Zeroizing<Vec<u8>> = match (args.format, &passphrase) {
        (FormatArg::Pem, None) => zeroize::Zeroizing::new(key.to_pem()?.as_bytes().to_vec()),
        (FormatArg::Pem, Some(pw)) => {
            zeroize::Zeroizing::new(key.to_encrypted_pem(pw)?.as_bytes().to_vec())
        }
        (FormatArg::Der, None) => key.to_pkcs8_der()?.to_bytes(),
        (FormatArg::Der, Some(pw)) => key.to_encrypted_der(pw)?.to_bytes(),
    };
    keyfile::write_private(&args.out, &encoded, args.force)?;
    let lms_files = match (key.as_lms(), caches) {
        (Some(lms), Some(caches)) => Some(crate::lms_state::create(
            &args.out, lms, caches, args.force,
        )?),
        _ => None,
    };

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "algorithm: {}", key.algorithm()).map_err(out_error)?;
    if let Some(lms) = key.as_lms() {
        writeln!(stdout, "parameter set: {}", lms.parameter_set()).map_err(out_error)?;
    }
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
    if let (Some(lms), Some((state, journal))) = (key.as_lms(), &lms_files) {
        writeln!(stdout, "signatures: {}", lms.leaves()).map_err(out_error)?;
        writeln!(stdout, "state: {} (next leaf 0)", state.display()).map_err(out_error)?;
        writeln!(stdout, "journal: {}", journal.display()).map_err(out_error)?;
        writeln!(
            io::stderr().lock(),
            "note: LMS/HSS keys are stateful: every signature uses up one of {} leaves, \
             recorded in {} and {}. Sign only with keelsign, keep the three files together, \
             never copy the key to a second machine and never restore it from a backup \
             (docs/keys.md#stateful-lms-keys).",
            lms.leaves(),
            state.display(),
            journal.display()
        )
        .map_err(out_error)?;
    }
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
