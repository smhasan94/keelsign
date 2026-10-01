//! Reading and writing key files and passphrases.
//!
//! Private key files are created with mode 0600 on Unix. An existing output file is
//! never replaced unless `--force` is given; with `--force` the new file is written to a
//! temporary file in the same directory and renamed over the old one.

use crate::cli::PassphraseArgs;
use crate::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn io_error(what: &str, path: &Path, source: io::Error) -> Error {
    Error::Io {
        what: format!("{what} {}", path.display()),
        source,
    }
}

/// Fail with [`Error::Exists`] if `path` exists (as anything, even a dangling symlink)
/// and `force` is not set. Checked before any work is done; the write itself is
/// race-free (see [`write_private`]).
pub fn ensure_absent(path: &Path, force: bool) -> Result<(), Error> {
    if !force && fs::symlink_metadata(path).is_ok() {
        return Err(Error::Exists(path.to_path_buf()));
    }
    Ok(())
}

/// Write a private key file: mode 0600 on Unix, never replacing an existing file unless
/// `force`. A partly written file is removed.
pub fn write_private(path: &Path, bytes: &[u8], force: bool) -> Result<(), Error> {
    write_file(path, bytes, force, true)
}

/// Write a public key file with the default mode, never replacing an existing file
/// unless `force`.
pub fn write_public(path: &Path, bytes: &[u8], force: bool) -> Result<(), Error> {
    write_file(path, bytes, force, false)
}

fn open_new(path: &Path, private: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    options.open(path)
}

/// Write `bytes` to a newly created `path`, then flush them to disk; on failure remove
/// the partial file.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), Error> {
    let mut file = open_new(path, private).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::Exists(path.to_path_buf())
        } else {
            io_error("create", path, e)
        }
    })?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(io_error("write", path, e));
    }
    Ok(())
}

/// `.<name>.keelsign-tmp-<pid>` next to `path`.
fn temp_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or_else(|| {
        Error::Usage(format!(
            "output path {} does not name a file",
            path.display()
        ))
    })?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".keelsign-tmp-{}", std::process::id()));
    Ok(path.with_file_name(temp_name))
}

fn write_file(path: &Path, bytes: &[u8], force: bool, private: bool) -> Result<(), Error> {
    if !force {
        return write_new(path, bytes, private);
    }
    let temp = temp_path(path)?;
    write_new(&temp, bytes, private).map_err(|e| match e {
        // A stale temporary file from an interrupted run: report it, not the target.
        Error::Exists(p) => io_error(
            "create",
            &p,
            io::Error::new(io::ErrorKind::AlreadyExists, "temporary file exists"),
        ),
        other => other,
    })?;
    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(io_error("replace", path, e));
    }
    Ok(())
}

/// The passphrase from `--passphrase-file` (its first line, without the line
/// terminator, like OpenSSL's `-passin file:`) or `--passphrase-env`, or `None` if
/// neither is given. An empty passphrase is a usage error.
pub fn read_passphrase(args: &PassphraseArgs) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    if let Some(path) = &args.passphrase_file {
        let contents =
            Zeroizing::new(fs::read(path).map_err(|e| io_error("read passphrase file", path, e))?);
        let line = contents.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Err(Error::Usage(format!(
                "the passphrase file {} is empty (its first line is the passphrase)",
                path.display()
            )));
        }
        return Ok(Some(Zeroizing::new(line.to_vec())));
    }
    if let Some(var) = &args.passphrase_env {
        let value = std::env::var_os(var).ok_or_else(|| {
            Error::Usage(format!(
                "--passphrase-env: the environment variable {var} is not set"
            ))
        })?;
        let value = Zeroizing::new(value.into_string().map_err(|_| {
            Error::Usage(format!(
                "--passphrase-env: the environment variable {var} is not valid Unicode"
            ))
        })?);
        if value.is_empty() {
            return Err(Error::Usage(format!(
                "--passphrase-env: the environment variable {var} is empty"
            )));
        }
        return Ok(Some(Zeroizing::new(value.as_bytes().to_vec())));
    }
    Ok(None)
}

/// The contents of a key file.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, Error> {
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| io_error("read key file", path, e))
}
