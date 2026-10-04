//! The in-house LMS/HSS signer (RFC 8554, NIST SP 800-208): LMS_SHA256_M32_H{5..25}
//! with LMOTS_SHA256_N32_W8, one or two HSS levels. keelsign's CLI generates H10, H15
//! and H20 keys; the other heights exist for tests.
//!
//! - One-time private keys follow RFC 8554 Appendix A:
//!   `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.
//! - The randomizer `C` of each signature is derived the same way with `i = 0xFFFD`, the
//!   convention of the Cisco hash-sigs reference implementation (RFC 8554 Appendix A
//!   specifies only the one-time key derivation), so signing is deterministic:
//!   `C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)`. A leaf is never
//!   used twice (the state file, [`crate::lms_state`], enforces that); a deterministic
//!   `C` means a repeated top-level signature over the same bottom-tree public key (after
//!   a crash in a rollover) is byte-identical, not a second one-time signature.
//! - With two levels the bottom tree `i` (signed by top-level leaf `i`) is derived from
//!   the stored second-level `SEED_1` and `I_1`: tree 0 uses them as they are, tree
//!   `i > 0` uses `SEED_1,i = H(SEED_1 || u32str(i) || "keelsign-hss-seed")` and
//!   `I_1,i = H(I_1 || u32str(i) || "keelsign-hss-id")[..16]`.
//! - Signing reads the authentication path from a [`NodeCache`] (the tree nodes at
//!   heights `>= floor`, kept in the state file) and recomputes the `2^floor` leaves of
//!   the one subtree below it.
//!
//! Every signature keelsign writes is also verified with `keelsign_verify` before the
//! image is written (`crate::sign::self_check`).

use sha2::block_api::compress256;
use sha2::{Digest as _, Sha256};
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

/// LMOTS_SHA256_N32_W8, the only LM-OTS parameter set keelsign signs with.
pub const LMOTS_SHA256_N32_W8: u32 = 0x04;
/// Hash length n = m in bytes (SHA-256).
pub const N: usize = 32;
/// Number of Winternitz chains for N32 W8 (RFC 8554 Appendix B).
pub const P: usize = 34;
/// Length of the key-pair identifier `I`.
pub const ID_LEN: usize = 16;
/// Length of a tree's secret `SEED`.
pub const SEED_LEN: usize = 32;
/// Length of an LMS public key: `u32 lms_type || u32 lmots_type || I || T[1]`.
pub const LMS_PUBLIC_KEY_LEN: usize = 8 + ID_LEN + N;
/// Length of an HSS public key: `u32 L || LMS public key`.
pub const HSS_PUBLIC_KEY_LEN: usize = 4 + LMS_PUBLIC_KEY_LEN;
/// The most HSS levels keelsign signs with (keelsign-verify's device default accepts two).
pub const MAX_LEVELS: usize = 2;
/// The cache floor keelsign keeps in state files: tree nodes at heights `>= 10`, so a
/// signature recomputes at most 1,024 leaves.
pub const DEFAULT_CACHE_FLOOR: u8 = 10;
/// Version byte of the private-key blob ([`HssPrivateKey::to_blob`]).
pub const BLOB_VERSION: u8 = 1;

/// Domain-separation constants, RFC 8554 §7.1.
const D_PBLC: [u8; 2] = 0x8080u16.to_be_bytes();
const D_MESG: [u8; 2] = 0x8181u16.to_be_bytes();
const D_LEAF: [u8; 2] = 0x8282u16.to_be_bytes();
const D_INTR: [u8; 2] = 0x8383u16.to_be_bytes();

/// The chain index used to derive `C` with the Appendix A construction, following the
/// Cisco hash-sigs reference implementation (not part of RFC 8554 itself).
const C_INDEX: u16 = 0xFFFD;

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Why a key, cache or signing request is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LmsError {
    /// The leaf index is past the last leaf.
    LeafOutOfRange {
        /// The leaf asked for.
        leaf: u64,
        /// The number of leaves.
        leaves: u64,
    },
    /// A cache does not fit its tree, or a cached node does not match the key.
    Cache(String),
    /// A malformed private-key blob.
    Corrupt(String),
    /// A well-formed private key keelsign does not sign with.
    Unsupported(String),
    /// The operating system's random-number generator failed.
    Rng(String),
}

impl fmt::Display for LmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeafOutOfRange { leaf, leaves } => {
                write!(
                    f,
                    "leaf {leaf} is out of range (the key has {leaves} leaves)"
                )
            }
            Self::Cache(reason) => write!(f, "LMS tree cache: {reason}"),
            Self::Corrupt(reason) => write!(f, "corrupt LMS/HSS private key: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported LMS/HSS private key: {reason}"),
            Self::Rng(reason) => write!(f, "random-number generator failed: {reason}"),
        }
    }
}

impl std::error::Error for LmsError {}

/// An LMS parameter set keelsign signs with: LMS_SHA256_M32_H{5,10,15,20,25} with
/// LMOTS_SHA256_N32_W8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmsParams {
    h: u8,
}

impl LmsParams {
    /// The parameter set of tree height `h` (5, 10, 15, 20 or 25).
    pub const fn from_height(h: u8) -> Option<Self> {
        match h {
            5 | 10 | 15 | 20 | 25 => Some(Self { h }),
            _ => None,
        }
    }

    /// The parameter set with these IANA typecodes, if keelsign signs with it.
    pub const fn from_typecodes(lms_type: u32, lmots_type: u32) -> Option<Self> {
        if lmots_type != LMOTS_SHA256_N32_W8 {
            return None;
        }
        match lms_type {
            0x05 => Self::from_height(5),
            0x06 => Self::from_height(10),
            0x07 => Self::from_height(15),
            0x08 => Self::from_height(20),
            0x09 => Self::from_height(25),
            _ => None,
        }
    }

    /// The tree height `h`.
    pub const fn height(self) -> u8 {
        self.h
    }

    /// The LMS typecode (0x05–0x09).
    pub const fn lms_type(self) -> u32 {
        self.h as u32 / 5 + 4
    }

    /// The LM-OTS typecode (always LMOTS_SHA256_N32_W8).
    pub const fn lmots_type(self) -> u32 {
        LMOTS_SHA256_N32_W8
    }

    /// The number of leaves, `2^h`.
    pub const fn leaves(self) -> u64 {
        1u64 << self.h
    }

    /// The IANA name, for example `LMS_SHA256_M32_H10`.
    pub fn name(self) -> String {
        format!("LMS_SHA256_M32_H{}", self.h)
    }

    /// Length of one LMS signature (RFC 8554 §5.4): `4 + (4 + n(p + 1)) + 4 + m·h`.
    pub const fn signature_len(self) -> usize {
        4 + 4 + N * (P + 1) + 4 + N * self.h as usize
    }
}

/// SHA-256 of the 55-byte message in `block[..55]`, whose padding (`0x80`, the bit
/// length 440) is already in `block[55..]`: one compression.
fn hash_one_block(block: &[u8; 64]) -> [u8; 32] {
    let mut state = SHA256_IV;
    compress256(&mut state, std::slice::from_ref(block));
    let mut out = [0u8; 32];
    for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }
    out
}

/// The single SHA-256 block of `I || u32str(q) || u16str(i) || u8str(j) || value(32)`
/// (55 bytes), the input of every Winternitz chain step and of the Appendix A
/// derivation. Holds secret values; wiped on drop.
struct ChainBlock([u8; 64]);

impl ChainBlock {
    const I: usize = 20;
    const J: usize = 22;
    const VALUE: usize = 23;
    const END: usize = 55;

    fn new(id: &[u8; ID_LEN], q: u32) -> Self {
        let mut block = [0u8; 64];
        block[..ID_LEN].copy_from_slice(id);
        block[ID_LEN..Self::I].copy_from_slice(&q.to_be_bytes());
        block[Self::END] = 0x80;
        block[56..].copy_from_slice(&((Self::END as u64) * 8).to_be_bytes());
        Self(block)
    }

    fn set_i(&mut self, i: u16) {
        self.0[Self::I..Self::J].copy_from_slice(&i.to_be_bytes());
    }

    /// `H(I || q || i || j || value)` with the current `i`.
    fn step(&mut self, j: u8, value: &[u8; N]) -> [u8; N] {
        self.0[Self::J] = j;
        self.0[Self::VALUE..Self::END].copy_from_slice(value);
        hash_one_block(&self.0)
    }
}

impl Drop for ChainBlock {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// SHA-256 of the concatenation of `parts`.
fn sha256(parts: &[&[u8]]) -> [u8; N] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `Cksm(Q)` for W8 (RFC 8554 Algorithm 2; ls = 0) as `u16str`.
fn checksum_w8(q: &[u8; N]) -> [u8; 2] {
    let sum: u16 = q.iter().map(|&b| u16::from(255 - b)).sum();
    sum.to_be_bytes()
}

/// The cached nodes of one LMS tree: `T[r]` for every node at height `>= floor`, that
/// is `r` in `1 .. 2^(h - floor + 1)` (heap order, the root first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeCache {
    height: u8,
    floor: u8,
    nodes: Vec<[u8; N]>,
}

impl NodeCache {
    /// A cache of a tree of height `height` holding the nodes at heights `>= floor`;
    /// `nodes` must have exactly `2^(height - floor + 1) - 1` entries.
    pub fn from_nodes(height: u8, floor: u8, nodes: Vec<[u8; N]>) -> Result<Self, LmsError> {
        if floor > height || height > 25 {
            return Err(LmsError::Cache(format!(
                "cache floor {floor} is above the tree height {height}"
            )));
        }
        let expected = (2usize << (height - floor)) - 1;
        if nodes.len() != expected {
            return Err(LmsError::Cache(format!(
                "a height-{height} tree cached from height {floor} has {expected} nodes, not {}",
                nodes.len()
            )));
        }
        Ok(Self {
            height,
            floor,
            nodes,
        })
    }

    /// The lowest cached height.
    pub fn floor(&self) -> u8 {
        self.floor
    }

    /// The height of the tree.
    pub fn height(&self) -> u8 {
        self.height
    }

    /// The cached nodes, root first.
    pub fn nodes(&self) -> &[[u8; N]] {
        &self.nodes
    }

    /// The root `T[1]`.
    pub fn root(&self) -> [u8; N] {
        self.nodes.first().copied().unwrap_or([0; N])
    }

    /// The node `T[r]`, if it is cached.
    fn get(&self, r: u32) -> Option<&[u8; N]> {
        self.nodes.get(usize::try_from(r).ok()?.checked_sub(1)?)
    }

    /// The same tree cached from the higher `floor` (a prefix of the nodes).
    pub fn with_floor(&self, floor: u8) -> Result<Self, LmsError> {
        if floor < self.floor {
            return Err(LmsError::Cache(format!(
                "cannot lower the cache floor from {} to {floor}",
                self.floor
            )));
        }
        let len = (2usize << self.height.saturating_sub(floor)) - 1;
        Self::from_nodes(
            self.height,
            floor,
            self.nodes.get(..len).unwrap_or_default().to_vec(),
        )
    }
}

/// One LMS tree: its parameter set, secret `SEED` and identifier `I`.
#[derive(Clone)]
pub struct LmsTree {
    params: LmsParams,
    seed: Zeroizing<[u8; SEED_LEN]>,
    id: [u8; ID_LEN],
}

impl fmt::Debug for LmsTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the seed.
        f.debug_struct("LmsTree")
            .field("params", &self.params)
            .field("id", &crate::keys::hex(&self.id))
            .finish_non_exhaustive()
    }
}

impl LmsTree {
    /// A tree from its parameter set, `SEED` and `I`.
    pub fn new(params: LmsParams, seed: Zeroizing<[u8; SEED_LEN]>, id: [u8; ID_LEN]) -> Self {
        Self { params, seed, id }
    }

    /// A tree with a fresh `SEED` and `I` from the operating system's random-number
    /// generator.
    pub fn generate(params: LmsParams) -> Result<Self, LmsError> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut id = [0u8; ID_LEN];
        getrandom::fill(seed.as_mut()).map_err(|e| LmsError::Rng(e.to_string()))?;
        getrandom::fill(&mut id).map_err(|e| LmsError::Rng(e.to_string()))?;
        Ok(Self::new(params, seed, id))
    }

    /// The parameter set.
    pub fn params(&self) -> LmsParams {
        self.params
    }

    /// The identifier `I`.
    pub fn id(&self) -> &[u8; ID_LEN] {
        &self.id
    }

    fn check_leaf(&self, q: u32) -> Result<(), LmsError> {
        if u64::from(q) < self.params.leaves() {
            Ok(())
        } else {
            Err(LmsError::LeafOutOfRange {
                leaf: u64::from(q),
                leaves: self.params.leaves(),
            })
        }
    }

    /// The deterministic randomizer `C` of leaf `q` (see the module documentation).
    pub fn derive_c(&self, q: u32) -> [u8; N] {
        let mut block = ChainBlock::new(&self.id, q);
        block.set_i(C_INDEX);
        block.step(0xFF, &self.seed)
    }

    /// The LM-OTS public key `K` of leaf `q` (RFC 8554 Algorithm 1).
    pub fn ots_public_key(&self, q: u32) -> [u8; N] {
        let mut k = Sha256::new();
        k.update(self.id);
        k.update(q.to_be_bytes());
        k.update(D_PBLC);
        let mut block = ChainBlock::new(&self.id, q);
        let mut tmp = Zeroizing::new([0u8; N]);
        for i in 0..P as u16 {
            block.set_i(i);
            *tmp = block.step(0xFF, &self.seed);
            for j in 0..255u8 {
                *tmp = block.step(j, &tmp);
            }
            k.update(*tmp);
        }
        k.finalize().into()
    }

    /// The leaf node `T[2^h + q]`.
    pub fn leaf_node(&self, q: u32) -> [u8; N] {
        let r = (1u32 << self.params.h) + q;
        sha256(&[&self.id, &r.to_be_bytes(), &D_LEAF, &self.ots_public_key(q)])
    }

    /// The interior node `T[r]` from its children.
    fn interior(&self, r: u32, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        sha256(&[&self.id, &r.to_be_bytes(), &D_INTR, left, right])
    }

    /// The leaf nodes of leaves `start .. start + count`, computed on every available
    /// core.
    fn leaf_nodes(&self, start: u32, count: u32) -> Vec<[u8; N]> {
        let count_usize = count as usize;
        let threads = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(count_usize / 8)
            .max(1);
        let mut out = vec![[0u8; N]; count_usize];
        if threads == 1 {
            for (node, q) in out.iter_mut().zip(start..) {
                *node = self.leaf_node(q);
            }
            return out;
        }
        let per_thread = count_usize.div_ceil(threads);
        std::thread::scope(|scope| {
            for (k, chunk) in out.chunks_mut(per_thread).enumerate() {
                let first = start + (k * per_thread) as u32;
                scope.spawn(move || {
                    for (node, q) in chunk.iter_mut().zip(first..) {
                        *node = self.leaf_node(q);
                    }
                });
            }
        });
        out
    }

    /// The subtree of height `height` whose leftmost leaf is `start` (a multiple of
    /// `2^height`), heap-ordered: index 1 is its root, indices `2^height ..` its leaves;
    /// index 0 is unused.
    pub fn subtree_nodes(&self, start: u32, height: u8) -> Vec<[u8; N]> {
        let leaves = self.leaf_nodes(start, 1 << height);
        self.reduce(start, height, &leaves)
    }

    /// The heap-ordered subtree of height `height` above `leaves` (`2^height` leaf nodes
    /// starting at leaf `start`).
    fn reduce(&self, start: u32, height: u8, leaves: &[[u8; N]]) -> Vec<[u8; N]> {
        let width = 1usize << height;
        let mut nodes = vec![[0u8; N]; 2 * width];
        for (slot, leaf) in nodes[width..].iter_mut().zip(leaves) {
            *slot = *leaf;
        }
        // The subtree root's node number in the whole tree.
        let root = ((1u32 << self.params.h) + start) >> height;
        for j in (1..width).rev() {
            let level = usize::BITS - 1 - j.leading_zeros();
            let r = (root << level) + (j as u32 - (1u32 << level));
            nodes[j] = self.interior(r, &nodes[2 * j], &nodes[2 * j + 1]);
        }
        nodes
    }

    /// Compute the whole tree and keep the nodes at heights `>= min(floor, h)`.
    pub fn build_nodes(&self, floor: u8) -> NodeCache {
        let h = self.params.h;
        let floor = floor.min(h);
        let subtrees = 1u32 << (h - floor);
        // Compute at least 1,024 leaves per batch, so the cores stay busy for low floors.
        let per_batch = (1u32 << floor).max(1024).min(1u32 << h);
        let subtrees_per_batch = per_batch >> floor;
        let mut nodes = vec![[0u8; N]; 2 * subtrees as usize - 1];
        let mut k = 0u32;
        while k < subtrees {
            let leaves = self.leaf_nodes(k << floor, per_batch);
            for (b, chunk) in leaves.chunks(1 << floor).enumerate() {
                let index = k + b as u32;
                let sub = self.reduce(index << floor, floor, chunk);
                nodes[(subtrees + index) as usize - 1] = sub[1];
            }
            k += subtrees_per_batch;
        }
        for r in (1..subtrees).rev() {
            let (left, right) = (nodes[2 * r as usize - 1], nodes[2 * r as usize]);
            nodes[r as usize - 1] = self.interior(r, &left, &right);
        }
        NodeCache {
            height: h,
            floor,
            nodes,
        }
    }

    /// The authentication path of leaf `q` (RFC 8554 §5.4.1), from `cache` and the
    /// `2^floor` leaves of the subtree below it. The recomputed subtree root must equal
    /// the cached node.
    pub fn auth_path(&self, q: u32, cache: &NodeCache) -> Result<Vec<[u8; N]>, LmsError> {
        self.check_leaf(q)?;
        let h = self.params.h;
        if cache.height != h {
            return Err(LmsError::Cache(format!(
                "the cache is for a height-{} tree, the key's tree has height {h}",
                cache.height
            )));
        }
        let floor = cache.floor;
        let start = (q >> floor) << floor;
        let subtree_root = ((1u32 << h) + start) >> floor;
        let subtree = self.subtree_nodes(start, floor);
        if cache.get(subtree_root) != subtree.get(1) {
            return Err(LmsError::Cache(format!(
                "cached node {subtree_root} does not match the key (the state file belongs \
                 to another key or is corrupt)"
            )));
        }
        let mut path = Vec::with_capacity(h as usize);
        let mut r = (1u32 << h) + q;
        for t in 0..h {
            let sibling = r ^ 1;
            let node = if t >= floor {
                cache.get(sibling)
            } else {
                let level = floor - t;
                let local = (1u32 << level) + (sibling - (subtree_root << level));
                subtree.get(local as usize)
            };
            path.push(*node.ok_or_else(|| LmsError::Cache(format!("node {sibling} is missing")))?);
            r >>= 1;
        }
        Ok(path)
    }

    /// The LMS public key `u32 lms_type || u32 lmots_type || I || T[1]` for the root.
    pub fn public_key(&self, root: &[u8; N]) -> [u8; LMS_PUBLIC_KEY_LEN] {
        let mut key = [0u8; LMS_PUBLIC_KEY_LEN];
        key[..4].copy_from_slice(&self.params.lms_type().to_be_bytes());
        key[4..8].copy_from_slice(&self.params.lmots_type().to_be_bytes());
        key[8..8 + ID_LEN].copy_from_slice(&self.id);
        key[8 + ID_LEN..].copy_from_slice(root);
        key
    }

    /// The LM-OTS signature of leaf `q` over `message` with randomizer `c` (RFC 8554
    /// Algorithm 3): `u32 lmots_type || C || y[0] || ... || y[p-1]`.
    pub fn ots_sign(&self, q: u32, c: &[u8; N], message: &[u8]) -> Vec<u8> {
        let q_hash: [u8; N] = sha256(&[&self.id, &q.to_be_bytes(), &D_MESG, c, message]);
        let checksum = checksum_w8(&q_hash);
        let mut signature = Vec::with_capacity(4 + N * (P + 1));
        signature.extend_from_slice(&LMOTS_SHA256_N32_W8.to_be_bytes());
        signature.extend_from_slice(c);
        let mut block = ChainBlock::new(&self.id, q);
        let mut tmp = Zeroizing::new([0u8; N]);
        for (i, &a) in q_hash.iter().chain(checksum.iter()).enumerate() {
            block.set_i(i as u16);
            *tmp = block.step(0xFF, &self.seed);
            for j in 0..a {
                *tmp = block.step(j, &tmp);
            }
            signature.extend_from_slice(&*tmp);
        }
        signature
    }

    /// The LMS signature of leaf `q` over `message` with randomizer `c` (RFC 8554
    /// Algorithm 5): `u32 q || LM-OTS signature || u32 lms_type || path`.
    pub fn lms_sign(
        &self,
        q: u32,
        c: &[u8; N],
        message: &[u8],
        cache: &NodeCache,
    ) -> Result<Vec<u8>, LmsError> {
        let path = self.auth_path(q, cache)?;
        let mut signature = Vec::with_capacity(self.params.signature_len());
        signature.extend_from_slice(&q.to_be_bytes());
        signature.extend_from_slice(&self.ots_sign(q, c, message));
        signature.extend_from_slice(&self.params.lms_type().to_be_bytes());
        for node in &path {
            signature.extend_from_slice(node);
        }
        Ok(signature)
    }
}

/// The second-level tree signed by top-level leaf `index`, with its cache, public key and
/// the top-level signature over that public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BottomTree {
    /// Which bottom tree (the top-level leaf that signs it).
    pub index: u64,
    /// Its cached nodes.
    pub cache: NodeCache,
    /// Its LMS public key.
    pub public_key: [u8; LMS_PUBLIC_KEY_LEN],
    /// The top-level LMS signature over `public_key`, made with top-level leaf `index`.
    pub top_signature: Vec<u8>,
}

/// The cached state a signature needs: the top tree's nodes and, with two levels, the
/// current bottom tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HssCaches {
    /// The top-level tree's cached nodes.
    pub top: NodeCache,
    /// The current bottom tree (two levels only).
    pub bottom: Option<BottomTree>,
}

/// An HSS private key with one or two levels: the top tree and the stored second-level
/// `SEED_1`, `I_1`, plus the HSS public key.
#[derive(Clone)]
pub struct HssPrivateKey {
    levels: Vec<LmsTree>,
    public_key: [u8; HSS_PUBLIC_KEY_LEN],
}

impl fmt::Debug for HssPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HssPrivateKey")
            .field("levels", &self.levels)
            .field("public_key", &crate::keys::hex(&self.public_key))
            .finish()
    }
}

impl HssPrivateKey {
    /// Generate a key with `levels` (1 or 2) levels of tree height `height`, with fresh
    /// randomness, and the caches its state file starts with (floor `floor`).
    pub fn generate(
        params: LmsParams,
        levels: u8,
        floor: u8,
    ) -> Result<(Self, HssCaches), LmsError> {
        if !(1..=MAX_LEVELS).contains(&usize::from(levels)) {
            return Err(LmsError::Unsupported(format!(
                "{levels} HSS levels; keelsign signs with 1 or 2"
            )));
        }
        let trees = (0..levels)
            .map(|_| LmsTree::generate(params))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_levels(trees, floor, None)
    }

    /// The key with these trees (top first), its public key and starting caches. With two
    /// levels the top-level signature over bottom tree 0 uses randomizer `c_top` if
    /// given (for known-answer tests), otherwise the derived one.
    pub fn from_levels(
        levels: Vec<LmsTree>,
        floor: u8,
        c_top: Option<[u8; N]>,
    ) -> Result<(Self, HssCaches), LmsError> {
        let top = levels
            .first()
            .ok_or_else(|| LmsError::Unsupported("no HSS levels".into()))?;
        if levels.len() > MAX_LEVELS {
            return Err(LmsError::Unsupported(format!(
                "{} HSS levels; keelsign signs with 1 or 2",
                levels.len()
            )));
        }
        let top_cache = top.build_nodes(floor);
        let mut public_key = [0u8; HSS_PUBLIC_KEY_LEN];
        public_key[..4].copy_from_slice(&(levels.len() as u32).to_be_bytes());
        public_key[4..].copy_from_slice(&top.public_key(&top_cache.root()));
        let key = Self { levels, public_key };
        let bottom = if key.levels.len() == 2 {
            Some(key.make_bottom(0, &top_cache, floor, c_top)?)
        } else {
            None
        };
        Ok((
            key,
            HssCaches {
                top: top_cache,
                bottom,
            },
        ))
    }

    /// The number of HSS levels `L`.
    pub fn levels(&self) -> usize {
        self.levels.len()
    }

    /// The stored trees, top first (level 1 is bottom tree 0).
    pub fn trees(&self) -> &[LmsTree] {
        &self.levels
    }

    /// The top tree's parameter set.
    pub fn top_params(&self) -> LmsParams {
        self.top().params
    }

    /// The HSS public key `u32 L || LMS public key of the top tree` (60 bytes).
    pub fn public_key(&self) -> &[u8; HSS_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// The number of signatures the key can make: the product of `2^h` over the levels.
    pub fn leaves(&self) -> u64 {
        self.levels
            .iter()
            .map(|t| t.params.leaves())
            .fold(1u64, u64::saturating_mul)
    }

    fn top(&self) -> &LmsTree {
        // `levels` is never empty: every constructor checks it.
        &self.levels[0]
    }

    /// The bottom tree's height (two levels only).
    fn bottom_height(&self) -> Option<u8> {
        self.levels.get(1).map(|t| t.params.h)
    }

    /// The parameter set as text, for example `LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=1`
    /// or `LMS_SHA256_M32_H10+LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=2`.
    pub fn parameter_set(&self) -> String {
        let trees: Vec<String> = self.levels.iter().map(|t| t.params.name()).collect();
        format!(
            "{}/LMOTS_SHA256_N32_W8, L={}",
            trees.join("+"),
            self.levels.len()
        )
    }

    /// Bottom tree `index`: tree 0 is the stored second level, tree `i > 0` is derived
    /// from it (see the module documentation).
    pub fn bottom_tree(&self, index: u64) -> Result<LmsTree, LmsError> {
        let stored = self
            .levels
            .get(1)
            .ok_or_else(|| LmsError::Cache("a one-level key has no bottom trees".into()))?;
        let i = u32::try_from(index)
            .ok()
            .filter(|&i| u64::from(i) < self.top().params.leaves())
            .ok_or(LmsError::LeafOutOfRange {
                leaf: index,
                leaves: self.top().params.leaves(),
            })?;
        if i == 0 {
            return Ok(stored.clone());
        }
        // Finalize straight into the zeroizing buffer: no plain copy of the child seed.
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut hasher = Sha256::new();
        hasher.update(stored.seed.as_ref());
        hasher.update(i.to_be_bytes());
        hasher.update(b"keelsign-hss-seed");
        hasher.finalize_into((&mut *seed).into());
        let id_hash = sha256(&[&stored.id, &i.to_be_bytes(), b"keelsign-hss-id"]);
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_hash[..ID_LEN]);
        Ok(LmsTree::new(stored.params, seed, id))
    }

    /// Build bottom tree `index`, its cache (floor `floor`) and the top-level signature
    /// over its public key with top-level leaf `index` (randomizer `c_top`, or derived).
    pub fn make_bottom(
        &self,
        index: u64,
        top_cache: &NodeCache,
        floor: u8,
        c_top: Option<[u8; N]>,
    ) -> Result<BottomTree, LmsError> {
        let tree = self.bottom_tree(index)?;
        let cache = tree.build_nodes(floor);
        let public_key = tree.public_key(&cache.root());
        let q = u32::try_from(index).map_err(|_| LmsError::LeafOutOfRange {
            leaf: index,
            leaves: self.top().params.leaves(),
        })?;
        let c = c_top.unwrap_or_else(|| self.top().derive_c(q));
        let top_signature = self.top().lms_sign(q, &c, &public_key, top_cache)?;
        Ok(BottomTree {
            index,
            cache,
            public_key,
            top_signature,
        })
    }

    /// The bottom tree that signs global leaf `leaf` (two levels: `leaf >> h_bottom`).
    pub fn bottom_index(&self, leaf: u64) -> Option<u64> {
        self.bottom_height().map(|h| leaf >> h)
    }

    /// Make sure `caches` hold the bottom tree that signs `leaf`, building the next one
    /// when `leaf` crosses into it (rollover). Returns whether the caches changed.
    pub fn ensure_bottom(
        &self,
        leaf: u64,
        caches: &mut HssCaches,
        floor: u8,
    ) -> Result<bool, LmsError> {
        let Some(index) = self.bottom_index(leaf) else {
            return Ok(false);
        };
        if caches.bottom.as_ref().is_some_and(|b| b.index == index) {
            return Ok(false);
        }
        let bottom = self.make_bottom(index, &caches.top, floor, None)?;
        caches.bottom = Some(bottom);
        Ok(true)
    }

    /// The HSS signature (RFC 8554 §6.2) of global leaf `leaf` over `message`, with the
    /// bottom-level randomizer `c` if given (for known-answer tests), otherwise the
    /// derived one. With two levels `caches.bottom` must be the bottom tree of `leaf`
    /// (see [`Self::ensure_bottom`]).
    pub fn sign(
        &self,
        leaf: u64,
        message: &[u8],
        caches: &HssCaches,
        c: Option<[u8; N]>,
    ) -> Result<Vec<u8>, LmsError> {
        let leaves = self.leaves();
        if leaf >= leaves {
            return Err(LmsError::LeafOutOfRange { leaf, leaves });
        }
        let mut signature = Vec::new();
        signature.extend_from_slice(&(self.levels.len() as u32 - 1).to_be_bytes());
        let (tree, q, cache) = match self.bottom_height() {
            None => (self.top().clone(), leaf, &caches.top),
            Some(h) => {
                let index = leaf >> h;
                let bottom = caches
                    .bottom
                    .as_ref()
                    .filter(|b| b.index == index)
                    .ok_or_else(|| {
                        LmsError::Cache(format!("bottom tree {index} is not prepared"))
                    })?;
                signature.extend_from_slice(&bottom.top_signature);
                signature.extend_from_slice(&bottom.public_key);
                (
                    self.bottom_tree(index)?,
                    leaf & ((1u64 << h) - 1),
                    &bottom.cache,
                )
            }
        };
        let q = u32::try_from(q).map_err(|_| LmsError::LeafOutOfRange { leaf, leaves })?;
        let c = c.unwrap_or_else(|| tree.derive_c(q));
        signature.extend_from_slice(&tree.lms_sign(q, &c, message, cache)?);
        Ok(signature)
    }

    /// The private-key blob (version 1), the `privateKey` of the PKCS#8 file:
    /// `u8 version | u32 L | L × (u32 lms_type | u32 lmots_type | SEED | I) | HSS public
    /// key (60 bytes)`.
    pub fn to_blob(&self) -> Zeroizing<Vec<u8>> {
        let mut blob = Zeroizing::new(Vec::with_capacity(
            1 + 4 + self.levels.len() * (8 + SEED_LEN + ID_LEN) + HSS_PUBLIC_KEY_LEN,
        ));
        blob.push(BLOB_VERSION);
        blob.extend_from_slice(&(self.levels.len() as u32).to_be_bytes());
        for tree in &self.levels {
            blob.extend_from_slice(&tree.params.lms_type().to_be_bytes());
            blob.extend_from_slice(&tree.params.lmots_type().to_be_bytes());
            blob.extend_from_slice(tree.seed.as_ref());
            blob.extend_from_slice(&tree.id);
        }
        blob.extend_from_slice(&self.public_key);
        blob
    }

    /// Read a private-key blob ([`Self::to_blob`]). The public key's `L`, typecodes and
    /// `I` must match the stored top tree; its root is checked when signing (the cached
    /// nodes, the key ID the state file is bound to, and the self-check of every image).
    pub fn from_blob(blob: &[u8]) -> Result<Self, LmsError> {
        let corrupt = |reason: &str| LmsError::Corrupt(reason.to_owned());
        let (&version, rest) = blob
            .split_first()
            .ok_or_else(|| corrupt("the private key is empty"))?;
        if version != BLOB_VERSION {
            return Err(LmsError::Unsupported(format!(
                "private-key blob version {version}; keelsign reads version {BLOB_VERSION}"
            )));
        }
        let mut rest = rest;
        let mut take = |n: usize| -> Result<&[u8], LmsError> {
            let (head, tail) = rest
                .split_at_checked(n)
                .ok_or_else(|| corrupt("the private key is truncated"))?;
            rest = tail;
            Ok(head)
        };
        let u32_of = |b: &[u8]| -> u32 { b.try_into().map(u32::from_be_bytes).unwrap_or(0) };
        let levels = u32_of(take(4)?);
        if !(1..=MAX_LEVELS as u32).contains(&levels) {
            return Err(LmsError::Unsupported(format!(
                "{levels} HSS levels; keelsign signs with 1 or 2"
            )));
        }
        let mut trees = Vec::with_capacity(levels as usize);
        for level in 0..levels {
            let lms_type = u32_of(take(4)?);
            let lmots_type = u32_of(take(4)?);
            let params = LmsParams::from_typecodes(lms_type, lmots_type).ok_or_else(|| {
                LmsError::Unsupported(format!(
                    "level {level} has LMS typecode {lms_type:#x} with LM-OTS typecode \
                     {lmots_type:#x}; keelsign signs with LMS_SHA256_M32_H5..H25 (0x05-0x09) \
                     and LMOTS_SHA256_N32_W8 (0x04)"
                ))
            })?;
            let mut seed = Zeroizing::new([0u8; SEED_LEN]);
            seed.copy_from_slice(take(SEED_LEN)?);
            let mut id = [0u8; ID_LEN];
            id.copy_from_slice(take(ID_LEN)?);
            trees.push(LmsTree::new(params, seed, id));
        }
        let mut public_key = [0u8; HSS_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(take(HSS_PUBLIC_KEY_LEN)?);
        if !rest.is_empty() {
            return Err(corrupt("bytes follow the public key"));
        }
        let top = trees
            .first()
            .ok_or_else(|| corrupt("the private key has no levels"))?;
        let mut expected = [0u8; 4 + 8 + ID_LEN];
        expected[..4].copy_from_slice(&levels.to_be_bytes());
        expected[4..8].copy_from_slice(&top.params.lms_type().to_be_bytes());
        expected[8..12].copy_from_slice(&top.params.lmots_type().to_be_bytes());
        expected[12..].copy_from_slice(&top.id);
        if public_key[..expected.len()] != expected {
            return Err(corrupt(
                "the public key's L, typecodes or I do not match the private key",
            ));
        }
        Ok(Self {
            levels: trees,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keelsign_verify::lms::{ParameterPolicy, verify, verify_with_policy};

    const MSG: &[u8] = b"keelsign LMS test message";

    fn tree(h: u8, label: u8) -> LmsTree {
        let params = LmsParams::from_height(h).expect("height");
        let seed = sha256(&[b"seed", &[label]]);
        let id = sha256(&[b"id", &[label]]);
        LmsTree::new(
            params,
            Zeroizing::new(seed),
            id[..ID_LEN].try_into().expect("16"),
        )
    }

    #[test]
    fn one_block_hash_is_sha256() {
        let mut block = ChainBlock::new(&[7; ID_LEN], 0x0102_0304);
        block.set_i(0x0506);
        let value = [9u8; N];
        let fast = block.step(0x0A, &value);
        let mut message = vec![7u8; ID_LEN];
        message.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0x0A]);
        message.extend_from_slice(&value);
        assert_eq!(message.len(), 55);
        assert_eq!(fast, sha256(&[&message]));
    }

    #[test]
    fn typecode_table_is_the_m32_w8_subset_of_keelsign_verify() {
        let default = ParameterPolicy::keelsign_default();
        let mut ours = 0;
        for lms in 0..=0x20u32 {
            for ots in 0..=0x20u32 {
                let signs = LmsParams::from_typecodes(lms, ots);
                if let Some(p) = signs {
                    assert!(default.allows(lms, ots), "{lms:#x}/{ots:#x}");
                    assert_eq!(p.lms_type(), lms);
                    assert_eq!(p.lmots_type(), ots);
                    ours += 1;
                }
                // Every M32 (0x05-0x09) W8 pair the verifier accepts, keelsign signs.
                if (0x05..=0x09).contains(&lms) && default.allows(lms, ots) {
                    assert!(signs.is_some(), "{lms:#x}/{ots:#x}");
                }
            }
        }
        assert_eq!(ours, 5);
        assert_eq!(LmsParams::from_height(10).map(|p| p.lms_type()), Some(6));
        assert_eq!(
            LmsParams::from_height(20).map(|p| p.name()).as_deref(),
            Some("LMS_SHA256_M32_H20")
        );
        assert_eq!(LmsParams::from_height(11), None);
        // The documented signature length: L=1 M32 H10 is 1,456 bytes with Nspk.
        assert_eq!(
            4 + LmsParams::from_height(10).expect("h10").signature_len(),
            1456
        );
    }

    /// `secrets.token_bytes` of scripts/gen_lms_vectors.py's fixture DRBG: block `k` is
    /// `SHA-256(SHA-256("keelsign-lms-fixtures:" + label) || u64be(k))`, each call taking
    /// whole blocks.
    struct Drbg {
        key: [u8; 32],
        counter: u64,
    }

    impl Drbg {
        fn new(label: &str) -> Self {
            Self {
                key: sha256(&[b"keelsign-lms-fixtures:", label.as_bytes()]),
                counter: 0,
            }
        }

        fn block(&mut self) -> [u8; 32] {
            let out = sha256(&[&self.key, &self.counter.to_be_bytes()]);
            self.counter += 1;
            out
        }
    }

    fn hsslms_tree(drbg: &mut Drbg, h: u8) -> LmsTree {
        let seed = drbg.block();
        let id = drbg.block();
        LmsTree::new(
            LmsParams::from_height(h).expect("height"),
            Zeroizing::new(seed),
            id[..ID_LEN].try_into().expect("16"),
        )
    }

    #[test]
    fn keygen_and_sign_match_hsslms_cases_301_302_303() {
        let fixture_bytes = include_bytes!("../../benches/lms-kat/fixtures/lms-host.bin");
        let fixture = lms_kat::Fixture::parse(fixture_bytes).expect("fixture");
        for (id, label, heights) in [
            (lms_kat::ids::M32_H5_L1, "m32w8-h5-l1", &[5u8][..]),
            (lms_kat::ids::M32_H5H5_L2, "m32w8-h5h5-l2", &[5, 5][..]),
            (lms_kat::ids::M32_H10_L1, "m32w8-h10-l1", &[10][..]),
        ] {
            let case = fixture.case(id).expect("case");
            let mut drbg = Drbg::new(label);
            let trees: Vec<LmsTree> = heights.iter().map(|&h| hsslms_tree(&mut drbg, h)).collect();
            // hsslms draws C for the top-level signature over the bottom key at key
            // generation, then C for the message signature.
            let c_top = (trees.len() == 2).then(|| drbg.block());
            let c = drbg.block();
            let (key, caches) =
                HssPrivateKey::from_levels(trees, DEFAULT_CACHE_FLOOR, c_top).expect("key");
            assert_eq!(key.public_key().as_slice(), case.pk, "case {id} public key");
            let signature = key.sign(0, case.msg, &caches, Some(c)).expect("sign");
            assert_eq!(signature, case.sig, "case {id} signature");
            verify(key.public_key(), case.msg, &signature).expect("verifies");
        }
    }

    #[test]
    fn every_leaf_of_an_h5_tree_verifies_with_keelsign_verify() {
        let (key, caches) = HssPrivateKey::from_levels(vec![tree(5, 1)], 3, None).expect("key");
        assert_eq!(key.leaves(), 32);
        let cnsa = ParameterPolicy::cnsa_2_0();
        for leaf in 0..32 {
            let signature = key.sign(leaf, MSG, &caches, None).expect("sign");
            assert_eq!(
                signature.len(),
                4 + LmsParams::from_height(5).expect("h5").signature_len()
            );
            verify(key.public_key(), MSG, &signature).expect("verifies");
            verify_with_policy(&cnsa, key.public_key(), MSG, &signature).expect("cnsa 2.0");
            // Deterministic.
            assert_eq!(key.sign(leaf, MSG, &caches, None).expect("sign"), signature);
            // Another message, a flipped bit: invalid.
            assert_eq!(
                verify(key.public_key(), b"another message", &signature),
                Err(keelsign_verify::Error::SignatureInvalid)
            );
            let mut flipped = signature.clone();
            let at = 8 + (leaf as usize * 37) % (flipped.len() - 8);
            flipped[at] ^= 0x10;
            assert!(
                verify(key.public_key(), MSG, &flipped).is_err(),
                "leaf {leaf} byte {at}"
            );
        }
        assert_eq!(
            key.sign(32, MSG, &caches, None),
            Err(LmsError::LeafOutOfRange {
                leaf: 32,
                leaves: 32
            })
        );
    }

    #[test]
    fn cached_auth_paths_equal_full_tree_paths() {
        for h in [5u8, 10] {
            let tree = tree(h, h);
            let full = tree.build_nodes(0);
            assert_eq!(full.nodes().len(), (2 << h) - 1);
            let leaves = 1u32 << h;
            let qs = [0, 1, 2, leaves / 2 - 1, leaves / 2, leaves - 2, leaves - 1];
            let expected: Vec<Vec<[u8; N]>> = qs
                .iter()
                .map(|&q| {
                    let mut r = leaves + q;
                    let mut path = Vec::new();
                    while r > 1 {
                        path.push(full.nodes()[(r ^ 1) as usize - 1]);
                        r >>= 1;
                    }
                    path
                })
                .collect();
            for floor in 0..=5u8 {
                let cache = full.with_floor(floor).expect("cache");
                assert_eq!(cache.nodes().len(), (2 << (h - floor)) - 1);
                assert_eq!(cache.root(), full.root());
                if floor == 5 || h == 5 {
                    // A cache built directly equals the truncated one.
                    assert_eq!(tree.build_nodes(floor), cache);
                }
                for (q, path) in qs.iter().zip(&expected) {
                    assert_eq!(
                        &tree.auth_path(*q, &cache).expect("path"),
                        path,
                        "h{h} floor {floor} q {q}"
                    );
                }
            }
            // A cache of another tree is refused.
            let other = self::tree(h, h + 1).build_nodes(5);
            assert!(matches!(tree.auth_path(0, &other), Err(LmsError::Cache(_))));
        }
    }

    #[test]
    fn two_level_rollover_signs_bottom_tree_1_with_top_leaf_1() {
        let (key, mut caches) =
            HssPrivateKey::from_levels(vec![tree(5, 7), tree(5, 8)], 2, None).expect("key");
        assert_eq!(key.leaves(), 1024);
        assert_eq!(caches.bottom.as_ref().map(|b| b.index), Some(0));
        // Bottom tree 0 is the stored second level.
        assert_eq!(key.bottom_tree(0).expect("tree").id(), key.trees()[1].id());
        for leaf in [0u64, 1, 31] {
            assert!(!key.ensure_bottom(leaf, &mut caches, 2).expect("ensure"));
            let signature = key.sign(leaf, MSG, &caches, None).expect("sign");
            verify(key.public_key(), MSG, &signature).expect("verifies");
        }
        // Leaf 32 needs bottom tree 1, signed by top-level leaf 1.
        assert!(matches!(
            key.sign(32, MSG, &caches, None),
            Err(LmsError::Cache(_))
        ));
        assert!(key.ensure_bottom(32, &mut caches, 2).expect("rollover"));
        let bottom = caches.bottom.clone().expect("bottom");
        assert_eq!(bottom.index, 1);
        assert_eq!(
            bottom.top_signature[..4],
            1u32.to_be_bytes(),
            "top-level leaf 1"
        );
        let tree1 = key.bottom_tree(1).expect("tree 1");
        assert_ne!(tree1.id(), key.trees()[1].id());
        assert_eq!(
            bottom.public_key,
            tree1.public_key(&tree1.build_nodes(0).root())
        );
        for leaf in [32u64, 33, 63] {
            let signature = key.sign(leaf, MSG, &caches, None).expect("sign");
            verify(key.public_key(), MSG, &signature).expect("verifies");
            let summary = crate::inspect::hss_summary(&signature).expect("summary");
            assert_eq!(summary.q, (leaf % 32) as u32);
        }
        // A rollover is deterministic: rebuilding bottom tree 1 gives the same signature.
        let again = key.make_bottom(1, &caches.top, 2, None).expect("again");
        assert_eq!(again, bottom);
        // Two levels are refused by the strict CNSA 2.0 policy.
        let signature = key.sign(40, MSG, &caches, None).expect("sign");
        assert_eq!(
            verify_with_policy(
                &ParameterPolicy::cnsa_2_0(),
                key.public_key(),
                MSG,
                &signature
            ),
            Err(keelsign_verify::Error::UnsupportedParameterSet)
        );
        assert!(matches!(
            key.sign(1024, MSG, &caches, None),
            Err(LmsError::LeafOutOfRange {
                leaf: 1024,
                leaves: 1024
            })
        ));
    }

    #[test]
    fn blob_round_trips_and_refuses_malformed_input() {
        let (key, _) =
            HssPrivateKey::from_levels(vec![tree(5, 3), tree(10, 4)], 10, None).expect("key");
        let blob = key.to_blob();
        assert_eq!(blob.len(), 1 + 4 + 2 * 56 + 60);
        let back = HssPrivateKey::from_blob(&blob).expect("blob");
        assert_eq!(back.public_key(), key.public_key());
        assert_eq!(back.to_blob(), blob);
        assert_eq!(
            back.parameter_set(),
            "LMS_SHA256_M32_H5+LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=2"
        );
        let refuse = |bytes: &[u8]| HssPrivateKey::from_blob(bytes).expect_err("refused");
        let mut bad = blob.to_vec();
        bad[0] = 2;
        assert!(matches!(refuse(&bad), LmsError::Unsupported(_)));
        assert!(matches!(
            refuse(&blob[..blob.len() - 1]),
            LmsError::Corrupt(_)
        ));
        let mut long = blob.to_vec();
        long.push(0);
        assert!(matches!(refuse(&long), LmsError::Corrupt(_)));
        // A typecode keelsign does not sign with (LMS_SHA256_M24_H5).
        let mut m24 = blob.to_vec();
        m24[8] = 0x0A;
        assert!(matches!(refuse(&m24), LmsError::Unsupported(_)));
        // L = 3.
        let mut l3 = blob.to_vec();
        l3[4] = 3;
        assert!(matches!(refuse(&l3), LmsError::Unsupported(_)));
        // A public key whose I does not match the top tree.
        let mut wrong_id = blob.to_vec();
        let at = wrong_id.len() - 60 + 12;
        wrong_id[at] ^= 1;
        assert!(matches!(refuse(&wrong_id), LmsError::Corrupt(_)));
        assert!(matches!(refuse(&[]), LmsError::Corrupt(_)));
    }

    #[test]
    fn debug_output_never_shows_the_seed() {
        let t = tree(5, 9);
        let seed_hex = crate::keys::hex(t.seed.as_ref());
        let (key, _) = HssPrivateKey::from_levels(vec![t], 5, None).expect("key");
        let text = format!("{key:?}");
        assert!(!text.contains(&seed_hex), "{text}");
        assert!(text.contains("LmsTree"));
    }
}
