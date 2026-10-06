//! The state of an LMS/HSS key: which leaf signs next, kept crash-safe next to the key
//! file (see `docs/keys.md`, "Stateful LMS keys").
//!
//! An LMS/HSS key `signing.pem` comes with two files `keygen` creates:
//!
//! - `signing.pem.state`: JSON with the next leaf, the number of leaves, the key ID it is
//!   bound to and the cached tree nodes (`format` `keelsign-lms-state`, `version` 1). It
//!   is only ever replaced whole: written to a temporary file, flushed, renamed over the
//!   old one, and the directory flushed.
//! - `signing.pem.journal`: an append-only log of `reserved <leaf> <unix-seconds>` lines,
//!   each flushed to disk, and the lock: `sign` holds an exclusive lock on it from before
//!   it reads the state until the signed image is written, so two processes never sign
//!   with the same key at once.
//!
//! `sign` [`reserve`]s a leaf before it computes any signature: under the lock it checks
//! the state file (it parses, belongs to the key, has a leaf left, and is not behind the
//! journal's highest reserved leaf, which would mean it was restored from a copy), writes
//! the state with the next leaf advanced, then appends the reservation to the journal.
//! A crash after that wastes the leaf, never reuses it.
//!
//! Debug builds (tests only) honour two hooks: `KEELSIGN_TEST_CRASH_AFTER_RESERVE=1`
//! aborts the process right after the journal append; `KEELSIGN_TEST_HOLD_LOCK=<path>`
//! creates `<path>.held` once the reservation is made and then waits (up to 60 s) until
//! `<path>` exists, holding the lock.

use crate::error::{Error, LmsStateError};
use crate::keys::hex;
use crate::lms_sign::{BottomTree, DEFAULT_CACHE_FLOOR, HssCaches, HssPrivateKey, N, NodeCache};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead as _, Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

/// The `format` of a state file.
pub const STATE_FORMAT: &str = "keelsign-lms-state";
/// The `version` of a state file.
pub const STATE_VERSION: u64 = 1;
/// The largest state file read (an H20 cache is about 128 KiB of hex per level).
pub const MAX_STATE_LEN: u64 = 16 << 20;
/// The longest journal line accepted.
const MAX_JOURNAL_LINE: usize = 128;

/// `<key>.state`, the state file of the key file `key`.
pub fn state_path(key: &Path) -> PathBuf {
    with_suffix(key, ".state")
}

/// `<key>.journal`, the journal (and lock) of the key file `key`.
pub fn journal_path(key: &Path) -> PathBuf {
    with_suffix(key, ".journal")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn state_error(path: &Path, reason: LmsStateError) -> Error {
    Error::LmsState {
        path: path.to_path_buf(),
        reason,
    }
}

fn corrupt(path: &Path, reason: impl Into<String>) -> Error {
    state_error(path, LmsStateError::Corrupt(reason.into()))
}

fn io_error(what: &str, path: &Path, source: io::Error) -> Error {
    Error::Io {
        what: format!("{what} {}", path.display()),
        source,
    }
}

/// Flush the directory holding `path`, so a rename in it survives a power loss.
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Options that create a new file with mode 0600 on Unix and fail if anything (a file or
/// a symbolic link) already has the name, so no link is ever followed.
fn create_new_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Create `path` (never replacing anything there), write `bytes` and flush them, then
/// flush the directory. A partly written file is removed.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_new_options().open(path)?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    drop(file);
    sync_dir(path)
}

/// Write `bytes` to `path`.
///
/// - With `create_new`, `path` must not exist (as anything, even a dangling link):
///   it is created exclusively (`O_EXCL`), written and flushed, and the directory
///   flushed; an existing `path` is [`Error::Exists`] and is left alone. This needs no
///   hard links, so it works on FAT, exFAT and SMB volumes too.
/// - Otherwise `path` is replaced whole: a new temporary file `.NAME.keelsign-tmp-PID`
///   next to it (created exclusively, so a link planted under that name is not followed;
///   a stale one from a crashed run is removed first), flushed, renamed over `path`, and
///   the directory flushed. Removing a stale temporary file is safe here, unlike the
///   key-file temporaries of `crate::keyfile` (which may hold a private key and are
///   reported instead): a state file or journal holds no secret, only public tree nodes,
///   leaf numbers and the key ID.
fn write_atomically(path: &Path, bytes: &[u8], create_new: bool) -> Result<(), Error> {
    if create_new {
        return write_new(path, bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Error::Exists(path.to_path_buf())
            } else {
                io_error("write", path, e)
            }
        });
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::Usage(format!("{} does not name a file", path.display())))?;
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".keelsign-tmp-{}", std::process::id()));
    let temp = path.with_file_name(temp_name);
    let result = (|| -> io::Result<()> {
        let mut file = match create_new_options().open(&temp) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Left by a crashed run with the same process ID (removing a link
                // removes the link, not its target).
                fs::remove_file(&temp)?;
                create_new_options().open(&temp)?
            }
            other => other?,
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        sync_dir(path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&temp);
        return Err(io_error("write", path, e));
    }
    Ok(())
}

/// The parsed state file of an LMS/HSS key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateFile {
    /// The key ID (over the HSS public key) the state belongs to.
    pub key_id: [u8; 16],
    /// The next leaf to sign with (global over both levels).
    pub next_leaf: u64,
    /// The number of leaves of the key.
    pub leaves: u64,
    /// The cached tree nodes.
    pub caches: HssCaches,
}

fn hex_nodes(nodes: &[[u8; N]]) -> String {
    nodes.iter().map(|n| hex(n)).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl StateFile {
    /// The state of a new key: leaf 0 next.
    pub fn new(key: &HssPrivateKey, caches: HssCaches) -> Self {
        Self {
            key_id: keelsign_verify::key_id_of(key.public_key()),
            next_leaf: 0,
            leaves: key.leaves(),
            caches,
        }
    }

    /// The JSON text of the state file.
    pub fn to_json(&self) -> String {
        let mut levels = vec![json!({
            "cache_floor": self.caches.top.floor(),
            "nodes": hex_nodes(self.caches.top.nodes()),
        })];
        if let Some(bottom) = &self.caches.bottom {
            levels.push(json!({
                "tree": bottom.index,
                "cache_floor": bottom.cache.floor(),
                "nodes": hex_nodes(bottom.cache.nodes()),
                "public_key": hex(&bottom.public_key),
                "top_signature": hex(&bottom.top_signature),
            }));
        }
        let value = json!({
            "format": STATE_FORMAT,
            "version": STATE_VERSION,
            "key_id": hex(&self.key_id),
            "next_leaf": self.next_leaf,
            "leaves": self.leaves,
            "levels": levels,
        });
        let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Parse the state file `text` (read from `path`, for messages) of `key`. A state
    /// bound to another key is [`LmsStateError::ForeignKey`], checked before the caches.
    pub fn parse(path: &Path, text: &[u8], key: &HssPrivateKey) -> Result<Self, Error> {
        let value: Value =
            serde_json::from_slice(text).map_err(|e| corrupt(path, format!("not JSON: {e}")))?;
        if value["format"] != STATE_FORMAT || value["version"] != STATE_VERSION {
            return Err(corrupt(
                path,
                format!("not a `{STATE_FORMAT}` version {STATE_VERSION} state file"),
            ));
        }
        let key_id: [u8; 16] = value["key_id"]
            .as_str()
            .and_then(unhex)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| corrupt(path, "`key_id` is not 16 bytes of hex"))?;
        let expected = keelsign_verify::key_id_of(key.public_key());
        if key_id != expected {
            return Err(state_error(
                path,
                LmsStateError::ForeignKey {
                    expected: hex(&expected),
                    found: hex(&key_id),
                },
            ));
        }
        let number = |field: &str| {
            value[field]
                .as_u64()
                .ok_or_else(|| corrupt(path, format!("`{field}` is not a number")))
        };
        let next_leaf = number("next_leaf")?;
        let leaves = number("leaves")?;
        if leaves != key.leaves() {
            return Err(corrupt(
                path,
                format!("`leaves` is {leaves}; the key has {}", key.leaves()),
            ));
        }
        if next_leaf > leaves {
            return Err(corrupt(path, "`next_leaf` is past the last leaf"));
        }
        let levels = value["levels"]
            .as_array()
            .filter(|l| l.len() == key.levels())
            .ok_or_else(|| {
                corrupt(
                    path,
                    format!("`levels` must list the key's {} levels", key.levels()),
                )
            })?;
        let cache = |level: &Value, height: u8| -> Result<NodeCache, Error> {
            let floor = level["cache_floor"]
                .as_u64()
                .and_then(|f| u8::try_from(f).ok())
                .ok_or_else(|| corrupt(path, "`cache_floor` is not a small number"))?;
            let bytes = level["nodes"]
                .as_str()
                .and_then(unhex)
                .ok_or_else(|| corrupt(path, "`nodes` is not hex"))?;
            let nodes = bytes
                .chunks(N)
                .map(|c| <[u8; N]>::try_from(c).ok())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| corrupt(path, "`nodes` is not a whole number of nodes"))?;
            NodeCache::from_nodes(height, floor, nodes).map_err(|e| corrupt(path, e.to_string()))
        };
        let trees = key.trees();
        let top = match (levels.first(), trees.first()) {
            (Some(level), Some(tree)) => cache(level, tree.params().height())?,
            _ => return Err(corrupt(path, "no top level")),
        };
        if top.root() != key.public_key()[4 + 24..] {
            return Err(corrupt(
                path,
                "the cached root does not match the key's public key",
            ));
        }
        let bottom = match (levels.get(1), trees.get(1)) {
            (Some(level), Some(tree)) => {
                let index = level["tree"]
                    .as_u64()
                    .ok_or_else(|| corrupt(path, "`tree` is not a number"))?;
                let public_key = level["public_key"]
                    .as_str()
                    .and_then(unhex)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| corrupt(path, "`public_key` is not an LMS public key"))?;
                let top_signature = level["top_signature"]
                    .as_str()
                    .and_then(unhex)
                    .filter(|s| s.len() == trees[0].params().signature_len())
                    .ok_or_else(|| corrupt(path, "`top_signature` is not an LMS signature"))?;
                Some(BottomTree {
                    index,
                    cache: cache(level, tree.params().height())?,
                    public_key,
                    top_signature,
                })
            }
            _ => None,
        };
        Ok(Self {
            key_id,
            next_leaf,
            leaves,
            caches: HssCaches { top, bottom },
        })
    }

    /// Read the state file of the key file `key_path`.
    pub fn read(key_path: &Path, key: &HssPrivateKey) -> Result<Self, Error> {
        let path = state_path(key_path);
        let text = read_state_bytes(&path)?;
        Self::parse(&path, &text, key)
    }

    /// Replace the state file `path` whole (see `write_atomically`).
    pub fn replace(&self, path: &Path) -> Result<(), Error> {
        write_atomically(path, self.to_json().as_bytes(), false)
    }

    /// Set the next leaf of the key file `key_path`'s state to `next_leaf`, under the
    /// key's lock. Skipping leaves is allowed; going back (which would reuse a leaf) or
    /// past the last leaf is refused. For tests that need a key near its end.
    pub fn set_next_leaf(key_path: &Path, next_leaf: u64) -> Result<(), Error> {
        let journal = Journal::open_locked(&journal_path(key_path))?;
        let path = state_path(key_path);
        let mut value: Value = serde_json::from_slice(&read_state_bytes(&path)?)
            .map_err(|e| corrupt(&path, format!("not JSON: {e}")))?;
        let current = value["next_leaf"].as_u64().unwrap_or(u64::MAX);
        let leaves = value["leaves"].as_u64().unwrap_or(0);
        let used = journal.high_water();
        if next_leaf < current || used.is_some_and(|u| next_leaf <= u) || next_leaf > leaves {
            return Err(Error::Usage(format!(
                "cannot set the next leaf to {next_leaf}: it is {current} (journal: {}) of {leaves}",
                used.map_or("none used".into(), |u| format!("leaf {u} used"))
            )));
        }
        value["next_leaf"] = json!(next_leaf);
        let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
        text.push('\n');
        write_atomically(&path, text.as_bytes(), false)
    }
}

fn read_state_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            state_error(path, LmsStateError::Missing)
        } else {
            io_error("read", path, e)
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read", path, e))?;
    if bytes.len() as u64 > MAX_STATE_LEN {
        return Err(corrupt(path, "larger than 16 MiB"));
    }
    Ok(bytes)
}

/// The first line of a journal: `keelsign-lms-journal 1 <key id in hex>`.
pub fn journal_header(key_id: &[u8; 16]) -> String {
    format!("{JOURNAL_MAGIC} {JOURNAL_VERSION} {}\n", hex(key_id))
}

/// The first word of a journal's header line.
pub const JOURNAL_MAGIC: &str = "keelsign-lms-journal";
/// The journal format version in its header line.
pub const JOURNAL_VERSION: u32 = 1;

/// `text` is a non-empty run of ASCII digits (no sign, no spaces), as a `u64`.
fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The journal of an LMS/HSS key, opened and exclusively locked.
#[derive(Debug)]
pub struct Journal {
    file: File,
    path: PathBuf,
    key_id: [u8; 16],
    high_water: Option<u64>,
}

impl Journal {
    /// Create the journal of the key with key ID `key_id` at `path`: its header line and
    /// no reservations (replacing an existing journal only with `force`).
    pub fn create(path: &Path, key_id: &[u8; 16], force: bool) -> Result<(), Error> {
        write_atomically(path, journal_header(key_id).as_bytes(), !force)
    }

    /// Open the journal at `path` and take its exclusive lock without waiting: another
    /// process holding it is [`LmsStateError::Locked`]. Reads its header (the key ID it
    /// belongs to) and the highest reserved leaf.
    pub fn open_locked(path: &Path) -> Result<Self, Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    state_error(path, LmsStateError::Missing)
                } else {
                    io_error("open", path, e)
                }
            })?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(state_error(path, LmsStateError::Locked));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(io_error("lock", path, e)),
        }
        file.seek(io::SeekFrom::Start(0))
            .map_err(|e| io_error("read", path, e))?;
        let (key_id, high_water) = Self::read_lines(path, io::BufReader::new(&file))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            key_id,
            high_water,
        })
    }

    /// The next line of `reader` without its newline: `Some((text, true))` for a complete
    /// line, `Some((text, false))` for a last line without its newline (torn by a
    /// crash), `None` at the end. A line of more than [`MAX_JOURNAL_LINE`] bytes (newline
    /// not counted), complete or not, is corrupt.
    fn next_line(
        path: &Path,
        reader: &mut impl io::BufRead,
        number: u64,
    ) -> Result<Option<(String, bool)>, Error> {
        let mut line = Vec::new();
        let read = reader
            .take(MAX_JOURNAL_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| io_error("read", path, e))?;
        if read == 0 {
            return Ok(None);
        }
        let complete = line.last() == Some(&b'\n');
        if complete {
            line.pop();
        }
        if line.len() > MAX_JOURNAL_LINE {
            return Err(corrupt(path, format!("journal line {number} is too long")));
        }
        let text = String::from_utf8(line)
            .map_err(|_| corrupt(path, format!("journal line {number} is not text")))?;
        Ok(Some((text, complete)))
    }

    /// The key ID of the header line and the highest leaf of the complete
    /// `reserved <leaf> <time>` lines after it; a torn last line is ignored.
    fn read_lines(
        path: &Path,
        mut reader: impl io::BufRead,
    ) -> Result<([u8; 16], Option<u64>), Error> {
        let no_header = || {
            corrupt(
                path,
                format!(
                    "the journal does not start with its `{JOURNAL_MAGIC} {JOURNAL_VERSION} \
                     <key id>` line"
                ),
            )
        };
        let key_id = match Self::next_line(path, &mut reader, 1)? {
            Some((header, true)) => {
                let mut words = header.split(' ');
                match (words.next(), words.next(), words.next(), words.next()) {
                    (Some(JOURNAL_MAGIC), Some(version), Some(id), None)
                        if version == JOURNAL_VERSION.to_string() =>
                    {
                        unhex(id).and_then(|b| <[u8; 16]>::try_from(b).ok())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
        .ok_or_else(no_header)?;
        let mut high = None;
        let mut number = 1u64;
        loop {
            number += 1;
            let Some((text, complete)) = Self::next_line(path, &mut reader, number)? else {
                return Ok((key_id, high));
            };
            if !complete {
                // A torn last line: the append it belongs to did not finish.
                return Ok((key_id, high));
            }
            let mut words = text.split(' ');
            let leaf = match (words.next(), words.next(), words.next(), words.next()) {
                (Some("reserved"), Some(leaf), Some(time), None) if digits(time).is_some() => {
                    digits(leaf)
                }
                _ => None,
            }
            .ok_or_else(|| {
                corrupt(
                    path,
                    format!("journal line {number} is not `reserved <leaf> <unix-seconds>`"),
                )
            })?;
            high = high.max(Some(leaf));
        }
    }

    /// The key ID the journal's header binds it to.
    pub fn key_id(&self) -> &[u8; 16] {
        &self.key_id
    }

    /// The highest leaf the journal records as reserved.
    pub fn high_water(&self) -> Option<u64> {
        self.high_water
    }

    /// Append `reserved <leaf> <unix-seconds>` and flush it to disk.
    pub fn append(&mut self, leaf: u64) -> Result<(), Error> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("reserved {leaf} {seconds}\n");
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| io_error("append to", &self.path, e))?;
        self.high_water = self.high_water.max(Some(leaf));
        Ok(())
    }
}

/// Write the state file and an empty journal of a new key `key_path` (after the key
/// file). Without `force` neither may exist.
pub fn create(
    key_path: &Path,
    key: &HssPrivateKey,
    caches: HssCaches,
    force: bool,
) -> Result<(PathBuf, PathBuf), Error> {
    let state = state_path(key_path);
    let journal = journal_path(key_path);
    write_atomically(
        &state,
        StateFile::new(key, caches).to_json().as_bytes(),
        !force,
    )?;
    let key_id = keelsign_verify::key_id_of(key.public_key());
    Journal::create(&journal, &key_id, force)?;
    Ok((state, journal))
}

/// A reserved leaf: the state file already names the next one and the journal records
/// this one. Holds the key's lock until dropped.
#[derive(Debug)]
pub struct Reservation {
    /// The reserved leaf (global over both levels).
    pub leaf: u64,
    /// The number of leaves of the key.
    pub leaves: u64,
    /// The state file.
    pub state_path: PathBuf,
    /// The caches to sign `leaf` with (the bottom tree of `leaf` prepared).
    pub caches: HssCaches,
    journal: Journal,
}

impl Reservation {
    /// The journal (and lock) this reservation holds.
    pub fn journal_path(&self) -> &Path {
        &self.journal.path
    }
}

/// Reserve the next leaf of the LMS/HSS key `key` (the key file `key_path`), before any
/// signature is computed. See the module documentation for the checks and their order.
pub fn reserve(key_path: &Path, key: &HssPrivateKey) -> Result<Reservation, Error> {
    let journal_path = journal_path(key_path);
    let mut journal = Journal::open_locked(&journal_path)?;
    let expected = keelsign_verify::key_id_of(key.public_key());
    if *journal.key_id() != expected {
        return Err(state_error(
            &journal_path,
            LmsStateError::ForeignKey {
                expected: hex(&expected),
                found: hex(journal.key_id()),
            },
        ));
    }
    let state_path = state_path(key_path);
    let mut state = StateFile::read(key_path, key)?;
    let leaf = state.next_leaf;
    if leaf >= state.leaves {
        return Err(Error::LeafIndexExhausted {
            key: key_path.to_path_buf(),
            leaves: state.leaves,
        });
    }
    if let Some(used) = journal.high_water()
        && leaf <= used
    {
        return Err(state_error(
            &state_path,
            LmsStateError::BehindJournal { next: leaf, used },
        ));
    }
    // Two levels: the bottom tree of `leaf` (a rollover builds the next one, signed by
    // the next top-level leaf, before anything is written).
    key.ensure_bottom(leaf, &mut state.caches, DEFAULT_CACHE_FLOOR)
        .map_err(|e| corrupt(&state_path, e.to_string()))?;
    let caches = state.caches.clone();
    state.next_leaf = leaf + 1;
    state.replace(&state_path)?;
    journal.append(leaf)?;
    test_hooks();
    Ok(Reservation {
        leaf,
        leaves: state.leaves,
        state_path,
        caches,
        journal,
    })
}

/// The debug-build test hooks (see the module documentation). Release builds have none.
#[cfg(debug_assertions)]
fn test_hooks() {
    if std::env::var_os("KEELSIGN_TEST_CRASH_AFTER_RESERVE").is_some_and(|v| v == "1") {
        std::process::abort();
    }
    if let Some(release) = std::env::var_os("KEELSIGN_TEST_HOLD_LOCK") {
        let release = PathBuf::from(release);
        let held = with_suffix(&release, ".held");
        let _ = fs::write(&held, b"");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !release.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(not(debug_assertions))]
fn test_hooks() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lms_sign::{LmsParams, LmsTree};
    use zeroize::Zeroizing;

    fn dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("keelsign-lms-state-{}", std::process::id()))
            .join(test);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn key(label: u8, levels: usize) -> (HssPrivateKey, HssCaches) {
        let trees = (0..levels)
            .map(|l| {
                LmsTree::new(
                    LmsParams::from_height(5).expect("h5"),
                    Zeroizing::new([label.wrapping_add(l as u8); 32]),
                    [label; 16],
                )
            })
            .collect();
        HssPrivateKey::from_levels(trees, DEFAULT_CACHE_FLOOR, None).expect("key")
    }

    /// A new key `dir/k.pem` (the key file itself is not needed here) with its state and
    /// journal.
    fn new_key(test: &str, levels: usize) -> (PathBuf, HssPrivateKey) {
        let path = dir(test).join("k.pem");
        let (key, caches) = key(1, levels);
        create(&path, &key, caches, false).expect("create");
        (path, key)
    }

    /// The `reserved` lines of the journal (after its header line).
    fn journal_lines(key_path: &Path) -> Vec<String> {
        let text = fs::read_to_string(journal_path(key_path)).expect("journal");
        let mut lines = text.lines();
        assert!(
            lines
                .next()
                .is_some_and(|h| h.starts_with("keelsign-lms-journal 1 "))
        );
        lines.map(str::to_owned).collect()
    }

    fn reason(e: Error) -> LmsStateError {
        match e {
            Error::LmsState { reason, .. } => reason,
            other => panic!("expected an LMS state error, got {other}"),
        }
    }

    #[test]
    fn sequential_reservations_are_consecutive() {
        let (path, key) = new_key("sequential", 1);
        for expected in 0..5u64 {
            let r = reserve(&path, &key).expect("reserve");
            assert_eq!((r.leaf, r.leaves), (expected, 32));
        }
        assert_eq!(StateFile::read(&path, &key).expect("state").next_leaf, 5);
        let lines = journal_lines(&path);
        assert_eq!(lines.len(), 5);
        for (i, line) in lines.iter().enumerate() {
            assert!(line.starts_with(&format!("reserved {i} ")), "{line}");
        }
        // Creating again without force is refused; the state is untouched.
        let (other, caches) = self::key(2, 1);
        assert!(matches!(
            create(&path, &other, caches, false),
            Err(Error::Exists(_))
        ));
        assert_eq!(StateFile::read(&path, &key).expect("state").next_leaf, 5);
    }

    #[test]
    fn replace_is_visible_on_disk_before_the_reservation_returns() {
        let (path, key) = new_key("visible", 1);
        let reservation = reserve(&path, &key).expect("reserve");
        // While the reservation (and its lock) is held, before anything is signed, the
        // state on disk already names the next leaf and the journal records this one.
        let on_disk = StateFile::read(&path, &key).expect("state");
        assert_eq!(on_disk.next_leaf, reservation.leaf + 1);
        assert_eq!(journal_lines(&path).len(), 1);
        assert!(journal_lines(&path)[0].starts_with("reserved 0 "));
        // No temporary file is left behind.
        let names: Vec<String> = fs::read_dir(path.parent().expect("dir"))
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.contains("keelsign-tmp")),
            "{names:?}"
        );
        drop(reservation);
    }

    #[test]
    fn reservation_without_use_skips_a_leaf() {
        let (path, key) = new_key("skip", 1);
        // A reservation dropped without signing (a crash after reserving) wastes the leaf.
        let first = reserve(&path, &key).expect("reserve").leaf;
        let second = reserve(&path, &key).expect("reserve").leaf;
        assert_eq!((first, second), (0, 1));
        // A torn last journal line (a crash during the append) is ignored.
        let mut file = OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .expect("open");
        file.write_all(b"reserved 9").expect("write");
        drop(file);
        assert_eq!(reserve(&path, &key).expect("reserve").leaf, 2);
    }

    #[test]
    fn rollback_is_detected_by_the_journal() {
        let (path, key) = new_key("rollback", 1);
        drop(reserve(&path, &key).expect("reserve"));
        let copy = fs::read(state_path(&path)).expect("copy");
        drop(reserve(&path, &key).expect("reserve"));
        drop(reserve(&path, &key).expect("reserve"));
        // Restore the copy taken when leaf 1 was next: leaves 1 and 2 are already used.
        fs::write(state_path(&path), &copy).expect("restore");
        let e = reserve(&path, &key).expect_err("refused");
        assert_eq!(e.exit_code(), 10);
        assert!(e.to_string().contains("restored from a copy"), "{e}");
        assert_eq!(reason(e), LmsStateError::BehindJournal { next: 1, used: 2 });
        // Nothing changed.
        assert_eq!(journal_lines(&path).len(), 3);
        assert_eq!(fs::read(state_path(&path)).expect("state"), copy);
    }

    #[test]
    fn lock_is_exclusive_across_opens() {
        let (path, key) = new_key("lock", 1);
        let held = reserve(&path, &key).expect("reserve");
        let e = reserve(&path, &key).expect_err("locked");
        assert_eq!(e.exit_code(), 10);
        assert_eq!(reason(e), LmsStateError::Locked);
        assert!(matches!(
            Journal::open_locked(&journal_path(&path)),
            Err(Error::LmsState {
                reason: LmsStateError::Locked,
                ..
            })
        ));
        drop(held);
        assert_eq!(reserve(&path, &key).expect("reserve").leaf, 1);
    }

    #[test]
    fn foreign_key_is_refused() {
        let (path, key) = new_key("foreign", 1);
        let (other, _) = self::key(2, 1);
        let e = reserve(&path, &other).expect_err("foreign");
        assert_eq!(e.exit_code(), 10);
        match reason(e) {
            LmsStateError::ForeignKey { expected, found } => {
                assert_eq!(
                    expected,
                    hex(&keelsign_verify::key_id_of(other.public_key()))
                );
                assert_eq!(found, hex(&keelsign_verify::key_id_of(key.public_key())));
            }
            other => panic!("{other:?}"),
        }
        assert!(journal_lines(&path).is_empty(), "nothing reserved");
        // Another key's journal (its header) is refused before the state file is read.
        let other_key = other;
        Journal::create(
            &journal_path(&path),
            &keelsign_verify::key_id_of(other_key.public_key()),
            true,
        )
        .expect("foreign journal");
        let e = reserve(&path, &key).expect_err("foreign journal");
        assert_eq!(e.exit_code(), 10);
        assert!(
            e.to_string()
                .contains("k.pem.journal belongs to another key"),
            "{e}"
        );
        match reason(e) {
            LmsStateError::ForeignKey { expected, found } => {
                assert_eq!(expected, hex(&keelsign_verify::key_id_of(key.public_key())));
                assert_eq!(
                    found,
                    hex(&keelsign_verify::key_id_of(other_key.public_key()))
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_corrupt_and_exhausted_states_are_refused() {
        let (path, key) = new_key("refused", 1);
        // Corrupt: not JSON, a wrong cached root, a malformed journal line.
        let good = fs::read(state_path(&path)).expect("state");
        fs::write(state_path(&path), b"{").expect("write");
        assert!(
            matches!(reason(reserve(&path, &key).expect_err("x")), LmsStateError::Corrupt(r) if r.contains("not JSON"))
        );
        let text = String::from_utf8(good.clone()).expect("utf8");
        let root = hex(&key.public_key()[28..]);
        fs::write(state_path(&path), text.replacen(&root, &"00".repeat(32), 1)).expect("write");
        assert!(
            matches!(reason(reserve(&path, &key).expect_err("x")), LmsStateError::Corrupt(r) if r.contains("cached root"))
        );
        fs::write(state_path(&path), &good).expect("write");
        let header = journal_header(&keelsign_verify::key_id_of(key.public_key()));
        let bad_journal = |body: &str| {
            fs::write(journal_path(&path), format!("{header}{body}")).expect("write");
            match reason(reserve(&path, &key).expect_err("refused")) {
                LmsStateError::Corrupt(r) => r,
                other => panic!("{body:?}: {other:?}"),
            }
        };
        assert!(bad_journal("reserved x 1\n").contains("journal line 2"));
        // Digits only: no sign, no spaces.
        assert!(bad_journal("reserved +5 1\n").contains("journal line 2"));
        assert!(bad_journal("reserved 5 -1\n").contains("journal line 2"));
        assert!(bad_journal("reserved  5 1\n").contains("journal line 2"));
        // The length cap holds for complete and torn lines alike.
        let long = format!("reserved {} 1", "1".repeat(MAX_JOURNAL_LINE));
        assert!(bad_journal(&format!("{long}\n")).contains("too long"));
        assert!(bad_journal(&long).contains("too long"));
        // A line of exactly the cap is fine, and so is a torn one below it.
        let at_cap = format!("reserved 0 {}", "0".repeat(MAX_JOURNAL_LINE - 11));
        assert_eq!(at_cap.len(), MAX_JOURNAL_LINE);
        fs::write(journal_path(&path), format!("{header}{at_cap}\nreserved 1")).expect("write");
        let journal = Journal::open_locked(&journal_path(&path)).expect("open");
        assert_eq!(journal.high_water(), Some(0));
        drop(journal);
        // A missing or wrong header.
        // The version token must be exactly `1` (not `01` or `+1`).
        let padded = header.replacen(" 1 ", " 01 ", 1);
        let signed = header.replacen(" 1 ", " +1 ", 1);
        for body in [
            "",
            "reserved 0 1\n",
            "keelsign-lms-journal 2 00\n",
            padded.as_str(),
            signed.as_str(),
        ] {
            fs::write(journal_path(&path), body).expect("write");
            assert!(
                matches!(reason(reserve(&path, &key).expect_err("x")), LmsStateError::Corrupt(r) if r.contains("does not start with")),
                "{body:?}"
            );
        }
        fs::write(journal_path(&path), &header).expect("write");
        // Missing.
        fs::remove_file(state_path(&path)).expect("rm");
        assert_eq!(
            reason(reserve(&path, &key).expect_err("x")),
            LmsStateError::Missing
        );
        fs::write(state_path(&path), &good).expect("write");
        fs::remove_file(journal_path(&path)).expect("rm");
        assert_eq!(
            reason(reserve(&path, &key).expect_err("x")),
            LmsStateError::Missing
        );
        Journal::create(
            &journal_path(&path),
            &keelsign_verify::key_id_of(key.public_key()),
            false,
        )
        .expect("journal");
        // Exhausted: the last leaf signs, then the key is used up.
        StateFile::set_next_leaf(&path, 31).expect("skip ahead");
        assert!(StateFile::set_next_leaf(&path, 30).is_err(), "never back");
        assert_eq!(reserve(&path, &key).expect("last").leaf, 31);
        let e = reserve(&path, &key).expect_err("exhausted");
        assert_eq!(e.exit_code(), 11);
        assert!(e.to_string().starts_with("LeafIndexExhausted:"), "{e}");
    }

    #[test]
    fn two_level_state_rolls_over_and_round_trips() {
        let (path, key) = new_key("two_levels", 2);
        assert_eq!(key.leaves(), 1024);
        let state = StateFile::read(&path, &key).expect("state");
        assert_eq!(state.caches.bottom.as_ref().map(|b| b.index), Some(0));
        StateFile::set_next_leaf(&path, 32).expect("skip to bottom tree 1");
        let r = reserve(&path, &key).expect("reserve");
        assert_eq!(r.leaf, 32);
        assert_eq!(r.caches.bottom.as_ref().map(|b| b.index), Some(1));
        let signature = key.sign(r.leaf, b"m", &r.caches, None).expect("sign");
        keelsign_verify::lms::verify(key.public_key(), b"m", &signature).expect("verifies");
        drop(r);
        // The rolled-over bottom tree is in the state file.
        let state = StateFile::read(&path, &key).expect("state");
        assert_eq!(state.next_leaf, 33);
        assert_eq!(state.caches.bottom.as_ref().map(|b| b.index), Some(1));
        let json: Value = serde_json::from_str(&state.to_json()).expect("json");
        assert_eq!(json["levels"][1]["tree"], 1);
        assert_eq!(json["format"], STATE_FORMAT);
    }
}
