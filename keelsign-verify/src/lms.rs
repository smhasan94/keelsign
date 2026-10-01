//! LMS/HSS signature verification (RFC 8554, NIST SP 800-208) over SHA-256 and
//! SHA-256/192, without heap or panics.
//!
//! [`verify`] checks an HSS signature (RFC 8554 §6.3) under the keelsign device default
//! [`ParameterPolicy::keelsign_default`]: LM-OTS W8 with SHA-256 (n = m = 32) or
//! SHA-256/192 (n = m = 24), any tree height H5–H25, at most [`MAX_HSS_LEVELS`] (2)
//! levels. A single LMS tree is an HSS key with one level (`L = 1`; RFC 8554 §6: the HSS
//! formats with `L = 1` are the LMS formats prepended by a fixed field).
//!
//! The strict [`ParameterPolicy::cnsa_2_0`] accepts the same W8 pairs but a single tree
//! only (`L = 1`): the CNSA 2.0 FAQ v2.1 (December 2024) does not allow the multi-tree
//! HSS for National Security Systems. Select it with [`verify_with_policy`] or, on the
//! device path, [`DefaultBackend::cnsa_2_0`](crate::DefaultBackend::cnsa_2_0) with
//! [`verify_pq_with`](crate::verify_pq_with). [`ParameterPolicy::rfc_8554_all_sets`] is
//! for host tests only and has no device entry point.
//!
//! Encodings (RFC 8554 §3.3, big-endian `u32str` / `u16str`):
//!
//! ```text
//! HSS public key: u32 L || LMS public key of level 0
//! LMS public key: u32 lms_type || u32 lmots_type || I (16) || T[1] (m)
//! HSS signature:  u32 Nspk || (LMS signature || LMS public key) * Nspk || LMS signature
//! LMS signature:  u32 q || LM-OTS signature || u32 lms_type || path (h * m)
//! LM-OTS sig:     u32 lmots_type || C (n) || y[0..p] (p * n)
//! ```
//!
//! Verification runs in two passes over the signature. The first pass parses every level,
//! checks every length and applies the parameter policy to every public key (the one
//! passed in and each one signed inside the signature) without hashing anything. The
//! second pass re-parses the same bytes and computes the hashes. So an unsupported
//! parameter set or a malformed signature is always reported as such, never as an invalid
//! signature, and no hashing is spent on it.
//!
//! Errors:
//!
//! - [`Error::UnsupportedParameterSet`]: an unknown typecode or a typecode pair outside
//!   the policy (at any level), `m != n`, a level whose hash differs from level 0's
//!   (SP 800-208 §4), or `L` outside `1..=max_levels`.
//! - [`Error::InvalidPublicKey`]: the public key is too short to hold its typecodes, or
//!   not exactly `4 + 24 + m` bytes.
//! - [`Error::MalformedSignature`]: the signature is shorter or longer than its typecodes
//!   dictate (truncated, or trailing bytes), or `Nspk + 1 != L`.
//! - [`Error::SignatureInvalid`]: a typecode inside the signature differs from the one in
//!   the public key it is checked against (RFC 8554 Algorithm 6a steps 2c and 2g),
//!   `q >= 2^h` (step 2i), or a computed root differs from the public key's `T[1]`.
//!
//! All values compared here (roots, typecodes) are public, so plain comparisons leak
//! nothing secret.

use sha2::{Digest, Sha256};

use crate::error::Error;

/// Accepted encoded public-key lengths in bytes: `4 (L) + 4 + 4 + 16 + m` with
/// m = 24 (SHA-256/192) or m = 32 (SHA-256).
pub const PUBLIC_KEY_LENS: [usize; 2] = [52, 60];

/// The most HSS levels [`ParameterPolicy::keelsign_default`] (and so [`verify`] and
/// [`verify_pq`](crate::verify_pq)) accepts. The strict [`ParameterPolicy::cnsa_2_0`]
/// accepts one.
pub const MAX_HSS_LEVELS: u32 = 2;

/// RFC 8554 §6: an HSS key has between one and eight levels.
const RFC_8554_MAX_LEVELS: u32 = 8;

/// Domain-separation constants, RFC 8554 §7.1 (and §4.5, §4.6, §5.3).
const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;

/// Length of the key-pair identifier `I` (RFC 8554 §4.2).
const I_LEN: usize = 16;

/// The largest n or m (SHA-256); SHA-256/192 uses the leftmost 24 bytes of the digest
/// (SP 800-208 §2.3, `T192`).
const MAX_HASH_LEN: usize = 32;

/// Error for failures that the tabulated parameter sets make impossible (a
/// coefficient index outside `Q || Cksm(Q)`, a checksum wider than 16 bits, `2^h` not
/// fitting in a `u32`). Fails closed.
const INTERNAL: Error = Error::SignatureInvalid;

/// An LM-OTS parameter set (RFC 8554 Table 1, SP 800-208 Table 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LmotsParams {
    typecode: u32,
    /// Hash output length in bytes.
    n: usize,
    /// Winternitz width in bits: 1, 2, 4 or 8.
    w: u8,
    /// Number of n-byte elements in the signature.
    p: u16,
    /// Checksum left shift.
    ls: u8,
}

/// An LMS parameter set (RFC 8554 Table 2, SP 800-208 Table 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LmsParams {
    typecode: u32,
    /// Node length in bytes.
    m: usize,
    /// Tree height.
    h: u8,
}

/// The LM-OTS parameter set with IANA typecode `typecode`, SHA-256 families only.
///
/// IANA "LM-OTS Signatures" registry: 0x01–0x04 are LMOTS_SHA256_N32_W{1,2,4,8}
/// (RFC 8554 §4.1 Table 1), 0x05–0x08 are LMOTS_SHA256_N24_W{1,2,4,8} (SP 800-208 §4.2
/// Table 3). p and ls follow RFC 8554 Appendix B. The SHAKE sets (0x09–0x10) are not
/// supported.
const fn lmots_params(typecode: u32) -> Option<LmotsParams> {
    let (n, w, p, ls) = match typecode {
        0x0000_0001 => (32, 1, 265, 7),
        0x0000_0002 => (32, 2, 133, 6),
        0x0000_0003 => (32, 4, 67, 4),
        0x0000_0004 => (32, 8, 34, 0),
        0x0000_0005 => (24, 1, 200, 8),
        0x0000_0006 => (24, 2, 101, 6),
        0x0000_0007 => (24, 4, 51, 4),
        0x0000_0008 => (24, 8, 26, 0),
        _ => return None,
    };
    Some(LmotsParams {
        typecode,
        n,
        w,
        p,
        ls,
    })
}

/// The LMS parameter set with IANA typecode `typecode`, SHA-256 families only.
///
/// IANA "LMS Signatures" registry: 0x05–0x09 are LMS_SHA256_M32_H{5,10,15,20,25}
/// (RFC 8554 §5.1 Table 2), 0x0A–0x0E are LMS_SHA256_M24_H{5,10,15,20,25} (SP 800-208
/// §4.2 Table 4). The SHAKE sets (0x0F–0x18) are not supported.
const fn lms_params(typecode: u32) -> Option<LmsParams> {
    let (m, h) = match typecode {
        0x0000_0005 => (32, 5),
        0x0000_0006 => (32, 10),
        0x0000_0007 => (32, 15),
        0x0000_0008 => (32, 20),
        0x0000_0009 => (32, 25),
        0x0000_000A => (24, 5),
        0x0000_000B => (24, 10),
        0x0000_000C => (24, 15),
        0x0000_000D => (24, 20),
        0x0000_000E => (24, 25),
        _ => return None,
    };
    Some(LmsParams { typecode, m, h })
}

/// Which typecode pairs a [`ParameterPolicy`] accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sets {
    /// LM-OTS W8 only.
    W8,
    /// Every tabulated SHA-256 / SHA-256/192 set, W1–W8.
    All,
}

/// Which LMS/LM-OTS parameter sets and how many HSS levels a verification accepts.
///
/// Every policy requires `m == n` for each level and the same hash (SHA-256 or
/// SHA-256/192) at every level (SP 800-208 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterPolicy {
    sets: Sets,
    max_levels: u32,
}

impl ParameterPolicy {
    /// The keelsign device default, used by [`verify`],
    /// [`DefaultBackend::new`](crate::DefaultBackend::new) and so by
    /// [`verify_pq`](crate::verify_pq): LMS_SHA256_M32_H{5..25} (0x05–0x09) with
    /// LMOTS_SHA256_N32_W8 (0x04), or LMS_SHA256_M24_H{5..25} (0x0A–0x0E) with
    /// LMOTS_SHA256_N24_W8 (0x08), the same hash at every level, at most
    /// [`MAX_HSS_LEVELS`] (2) levels.
    ///
    /// Two levels deviate from CNSA 2.0, which allows single-tree LMS only; use
    /// [`cnsa_2_0`](Self::cnsa_2_0) for National Security Systems.
    pub const fn keelsign_default() -> Self {
        Self {
            sets: Sets::W8,
            max_levels: MAX_HSS_LEVELS,
        }
    }

    /// Strict CNSA 2.0 (CNSA 2.0 FAQ v2.1, December 2024): the same W8 pairs as
    /// [`keelsign_default`](Self::keelsign_default), single tree only (`L = 1`).
    ///
    /// The FAQ approves LMS and XMSS for National Security Systems and says the
    /// multi-tree algorithms HSS and XMSS^MT "are not allowed", so an `L >= 2` public key
    /// is [`Error::UnsupportedParameterSet`] before its signature is read. On the device
    /// path, select it with [`DefaultBackend::cnsa_2_0`](crate::DefaultBackend::cnsa_2_0)
    /// and [`verify_pq_with`](crate::verify_pq_with).
    pub const fn cnsa_2_0() -> Self {
        Self {
            sets: Sets::W8,
            max_levels: 1,
        }
    }

    /// Every SHA-256 and SHA-256/192 parameter set of RFC 8554 and SP 800-208 (LM-OTS
    /// W1, W2, W4 and W8), up to the RFC's eight levels.
    ///
    /// **Host and test use only, never on a device**: it exists to check this
    /// implementation against published vectors outside the device policies (RFC 8554
    /// Test Case 2, the NIST ACVP LMS vectors). No device entry point reaches it:
    /// [`DefaultBackend`](crate::DefaultBackend) has no constructor for it, so neither
    /// [`verify_pq`](crate::verify_pq) nor [`verify_pq_with`](crate::verify_pq_with) with
    /// that backend can use it.
    pub const fn rfc_8554_all_sets() -> Self {
        Self {
            sets: Sets::All,
            max_levels: RFC_8554_MAX_LEVELS,
        }
    }

    /// The most HSS levels the policy accepts.
    pub const fn max_levels(&self) -> u32 {
        self.max_levels
    }

    /// Whether an LMS public key with these typecodes is accepted by the policy.
    pub const fn allows(&self, lms_typecode: u32, lmots_typecode: u32) -> bool {
        self.params(lms_typecode, lmots_typecode).is_some()
    }

    /// The parameter sets for a typecode pair, if the policy accepts it.
    const fn params(
        &self,
        lms_typecode: u32,
        lmots_typecode: u32,
    ) -> Option<(LmsParams, LmotsParams)> {
        let (Some(lms), Some(ots)) = (lms_params(lms_typecode), lmots_params(lmots_typecode))
        else {
            return None;
        };
        if lms.m != ots.n {
            return None;
        }
        match self.sets {
            Sets::W8 if ots.w != 8 => None,
            Sets::W8 | Sets::All => Some((lms, ots)),
        }
    }
}

/// Check the structure of an HSS public key without any parameter policy, as
/// [`TrustedKeys::new`](crate::TrustedKeys::new) does for every LMS/HSS key.
///
/// - `L` (the first four bytes) must be in `1..=8`, the RFC 8554 §6 maximum; otherwise
///   [`Error::UnsupportedParameterSet`].
/// - The level-0 LMS typecode must be a tabulated SHA-256 or SHA-256/192 set (0x05–0x0E);
///   otherwise [`Error::UnsupportedParameterSet`], since no length follows from it.
/// - The key must be exactly `4 + 24 + m` bytes for that typecode's m (52 for m = 24, 60
///   for m = 32); otherwise [`Error::InvalidPublicKey`].
///
/// The LM-OTS typecode, the parameter policy ([`ParameterPolicy::keelsign_default`]: W8
/// only, `m == n`, at most [`MAX_HSS_LEVELS`] levels; [`ParameterPolicy::cnsa_2_0`]: the
/// same with `L = 1`) and everything else are left to verification, so a well-formed key
/// outside the policy (a W2 key, or an `L = 2` key under `cnsa_2_0()`) is accepted here
/// and refused with [`Error::UnsupportedParameterSet`] when it verifies a signature.
pub fn check_public_key(public_key: &[u8]) -> Result<(), Error> {
    let mut rest = public_key;
    let levels = read_u32(&mut rest).ok_or(Error::InvalidPublicKey)?;
    if levels == 0 || levels > RFC_8554_MAX_LEVELS {
        return Err(Error::UnsupportedParameterSet);
    }
    let mut typecode = rest;
    let lms_type = read_u32(&mut typecode).ok_or(Error::InvalidPublicKey)?;
    let lms = lms_params(lms_type).ok_or(Error::UnsupportedParameterSet)?;
    if Some(rest.len()) == lms_public_key_len(&lms) {
        Ok(())
    } else {
        Err(Error::InvalidPublicKey)
    }
}

/// Verify an HSS `signature` over `message` under `public_key` with the keelsign device
/// default [`ParameterPolicy::keelsign_default`] (at most two levels).
///
/// For the strict single-tree CNSA 2.0 policy use
/// [`verify_with_policy`]`(&ParameterPolicy::cnsa_2_0(), ..)`. See the
/// [module documentation](self) for the encodings and the error mapping.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    verify_with_policy(
        &ParameterPolicy::keelsign_default(),
        public_key,
        message,
        signature,
    )
}

/// Verify an HSS `signature` over `message` under `public_key`, accepting the parameter
/// sets of `policy` (RFC 8554 §6.3).
///
/// See the [module documentation](self) for the encodings and the error mapping.
pub fn verify_with_policy(
    policy: &ParameterPolicy,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let (levels, top) = parse_hss_public_key(policy, public_key)?;
    // Pass 1: structure and policy for every level, no hashing.
    walk(policy, levels, &top, message, signature, false)?;
    // Pass 2: the same parse, now with the hash computations.
    walk(policy, levels, &top, message, signature, true)
}

/// An LMS public key (RFC 8554 §5.3) whose typecodes the policy accepts.
#[derive(Clone, Copy, Debug)]
struct LmsPublicKey<'a> {
    lms: LmsParams,
    ots: LmotsParams,
    /// The identifier `I`, [`I_LEN`] bytes.
    id: &'a [u8],
    /// The root `T[1]`, m bytes.
    root: &'a [u8],
}

/// One LMS signature (RFC 8554 §5.4), split by the lengths of the public key it is
/// checked against. The typecodes it carries are compared with the key's only when it
/// is verified.
#[derive(Clone, Copy, Debug)]
struct LmsSignature<'a> {
    q: u32,
    lmots_typecode: u32,
    /// The randomizer `C`, n bytes.
    c: &'a [u8],
    /// `y[0] || ... || y[p-1]`, p * n bytes.
    y: &'a [u8],
    lms_typecode: u32,
    /// `path[0] || ... || path[h-1]`, h * m bytes.
    path: &'a [u8],
}

/// Split `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(n)?;
    *rest = tail;
    Some(head)
}

/// `strTou32` of the next four bytes of `rest` (RFC 8554 §3.1.1).
fn read_u32(rest: &mut &[u8]) -> Option<u32> {
    let (head, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*head))
}

/// The typecode pair at the front of an LMS public key, if there are eight bytes.
fn peek_typecodes(bytes: &[u8]) -> Option<(u32, u32)> {
    let mut rest = bytes;
    Some((read_u32(&mut rest)?, read_u32(&mut rest)?))
}

/// `24 + m`: the length of an LMS public key (RFC 8554 §5.3).
fn lms_public_key_len(lms: &LmsParams) -> Option<usize> {
    lms.m.checked_add(8 + I_LEN)
}

/// Split an LMS public key of exactly [`lms_public_key_len`] bytes whose typecodes have
/// already been looked up.
fn split_lms_public_key(
    bytes: &[u8],
    lms: LmsParams,
    ots: LmotsParams,
) -> Option<LmsPublicKey<'_>> {
    let mut rest = bytes;
    let _typecodes = take(&mut rest, 8)?;
    let id = take(&mut rest, I_LEN)?;
    let root = take(&mut rest, lms.m)?;
    rest.is_empty()
        .then_some(LmsPublicKey { lms, ots, id, root })
}

/// Parse the HSS public key `u32str(L) || pub[0]` (RFC 8554 §6.1) and return `L` and the
/// level-0 LMS public key.
fn parse_hss_public_key<'a>(
    policy: &ParameterPolicy,
    public_key: &'a [u8],
) -> Result<(u32, LmsPublicKey<'a>), Error> {
    let mut rest = public_key;
    let levels = read_u32(&mut rest).ok_or(Error::InvalidPublicKey)?;
    let (lms_type, ots_type) = peek_typecodes(rest).ok_or(Error::InvalidPublicKey)?;
    let (lms, ots) = policy
        .params(lms_type, ots_type)
        .ok_or(Error::UnsupportedParameterSet)?;
    if levels == 0 || levels > policy.max_levels {
        return Err(Error::UnsupportedParameterSet);
    }
    // RFC 8554 Algorithm 6 step 2d: exactly 24 + m bytes.
    if Some(rest.len()) != lms_public_key_len(&lms) {
        return Err(Error::InvalidPublicKey);
    }
    let key = split_lms_public_key(rest, lms, ots).ok_or(Error::InvalidPublicKey)?;
    Ok((levels, key))
}

/// Parse the LMS public key signed inside an HSS signature (`publist[i]`, RFC 8554
/// §6.3) and return it with its encoded bytes, which are the message signed by the level
/// above. Its typecodes must be accepted by `policy` and use the same hash length as
/// level 0.
fn parse_signed_public_key<'a>(
    policy: &ParameterPolicy,
    hash_len: usize,
    rest: &mut &'a [u8],
) -> Result<(LmsPublicKey<'a>, &'a [u8]), Error> {
    let (lms_type, ots_type) = peek_typecodes(rest).ok_or(Error::MalformedSignature)?;
    let (lms, ots) = policy
        .params(lms_type, ots_type)
        .ok_or(Error::UnsupportedParameterSet)?;
    if lms.m != hash_len {
        return Err(Error::UnsupportedParameterSet);
    }
    let len = lms_public_key_len(&lms).ok_or(Error::MalformedSignature)?;
    let bytes = take(rest, len).ok_or(Error::MalformedSignature)?;
    let key = split_lms_public_key(bytes, lms, ots).ok_or(Error::MalformedSignature)?;
    Ok((key, bytes))
}

/// Parse the next LMS signature from `rest` with the lengths of `key`'s parameter sets:
/// `4 + (4 + n * (p + 1)) + 4 + m * h` bytes (RFC 8554 Algorithm 6a step 2).
fn parse_lms_signature<'a>(
    key: &LmsPublicKey<'_>,
    rest: &mut &'a [u8],
) -> Result<LmsSignature<'a>, Error> {
    let n = key.ots.n;
    let y_len = n
        .checked_mul(usize::from(key.ots.p))
        .ok_or(Error::MalformedSignature)?;
    let path_len = key
        .lms
        .m
        .checked_mul(usize::from(key.lms.h))
        .ok_or(Error::MalformedSignature)?;
    let q = read_u32(rest).ok_or(Error::MalformedSignature)?;
    let lmots_typecode = read_u32(rest).ok_or(Error::MalformedSignature)?;
    let c = take(rest, n).ok_or(Error::MalformedSignature)?;
    let y = take(rest, y_len).ok_or(Error::MalformedSignature)?;
    let lms_typecode = read_u32(rest).ok_or(Error::MalformedSignature)?;
    let path = take(rest, path_len).ok_or(Error::MalformedSignature)?;
    Ok(LmsSignature {
        q,
        lmots_typecode,
        c,
        y,
        lms_typecode,
        path,
    })
}

/// Walk the HSS signature `u32str(Nspk) || (sig[i] || pub[i+1]) * Nspk || sig[Nspk]`
/// (RFC 8554 §6.3). With `verify == false` it only parses and applies the policy; with
/// `verify == true` it also verifies every level, stopping at the first failure.
fn walk(
    policy: &ParameterPolicy,
    levels: u32,
    top: &LmsPublicKey<'_>,
    message: &[u8],
    signature: &[u8],
    verify: bool,
) -> Result<(), Error> {
    let mut rest = signature;
    let nspk = read_u32(&mut rest).ok_or(Error::MalformedSignature)?;
    // "if Nspk+1 is not equal to the number of levels L in pub: return INVALID"
    if nspk.checked_add(1) != Some(levels) {
        return Err(Error::MalformedSignature);
    }
    let mut key = *top;
    // `nspk < levels <= policy.max_levels`, so this loop is bounded by the policy.
    for _ in 0..nspk {
        let sig = parse_lms_signature(&key, &mut rest)?;
        let (child, child_bytes) = parse_signed_public_key(policy, top.lms.m, &mut rest)?;
        if verify {
            lms_verify(&key, &sig, child_bytes)?;
        }
        key = child;
    }
    let sig = parse_lms_signature(&key, &mut rest)?;
    if !rest.is_empty() {
        return Err(Error::MalformedSignature);
    }
    if verify {
        lms_verify(&key, &sig, message)?;
    }
    Ok(())
}

/// RFC 8554 Algorithm 6 steps 3–4 with Algorithm 6a: verify one LMS signature over
/// `message` under `key`.
fn lms_verify(key: &LmsPublicKey<'_>, sig: &LmsSignature<'_>, message: &[u8]) -> Result<(), Error> {
    // Algorithm 6a step 2c: otssigtype must be the public key's LM-OTS typecode.
    // Step 2g: sigtype must be the public key's LMS typecode.
    if sig.lmots_typecode != key.ots.typecode || sig.lms_typecode != key.lms.typecode {
        return Err(Error::SignatureInvalid);
    }
    // Step 2i: q < 2^h (h <= 25, so 2^h fits in a u32).
    let leaves = 1u32.checked_shl(u32::from(key.lms.h)).ok_or(INTERNAL)?;
    if sig.q >= leaves {
        return Err(Error::SignatureInvalid);
    }
    // Step 3: Kc from the LM-OTS signature (Algorithm 4b).
    let kc = lmots_candidate(&key.ots, key.id, sig.q, sig.c, sig.y, message)?;
    let kc = kc.get(..key.ots.n).ok_or(INTERNAL)?;
    // Step 4: the candidate root Tc.
    let m = key.lms.m;
    let mut node_num = leaves.checked_add(sig.q).ok_or(INTERNAL)?;
    // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
    let mut tmp = hash(
        &[key.id, &node_num.to_be_bytes(), &D_LEAF.to_be_bytes(), kc],
        m,
    )?;
    let mut path = sig.path;
    while node_num > 1 {
        // Pass 1 checked that the path is exactly h * m bytes, so this is defensive.
        let sibling = take(&mut path, m).ok_or(Error::MalformedSignature)?;
        let parent = (node_num / 2).to_be_bytes();
        let current = tmp.get(..m).ok_or(INTERNAL)?;
        tmp = if node_num % 2 == 1 {
            // tmp = H(I || u32str(node_num/2) || u16str(D_INTR) || path[i] || tmp)
            hash(
                &[key.id, &parent, &D_INTR.to_be_bytes(), sibling, current],
                m,
            )?
        } else {
            // tmp = H(I || u32str(node_num/2) || u16str(D_INTR) || tmp || path[i])
            hash(
                &[key.id, &parent, &D_INTR.to_be_bytes(), current, sibling],
                m,
            )?
        };
        node_num /= 2;
    }
    // Pass 1 guarantees the path length, so this is defensive.
    if !path.is_empty() {
        return Err(Error::MalformedSignature);
    }
    // Algorithm 6 step 4: Tc == T[1].
    if tmp.get(..m) == Some(key.root) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

/// RFC 8554 Algorithm 4b step 3: the LM-OTS public key candidate `Kc` from the
/// signature parts `C` and `y`, the message, and the identifiers `I` and `q`. The first
/// n bytes of the result are `Kc`.
fn lmots_candidate(
    ots: &LmotsParams,
    id: &[u8],
    q: u32,
    c: &[u8],
    y: &[u8],
    message: &[u8],
) -> Result<[u8; MAX_HASH_LEN], Error> {
    let n = ots.n;
    let q_bytes = q.to_be_bytes();
    // Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    let mut hasher = Sha256::new();
    hasher.update(id);
    hasher.update(q_bytes);
    hasher.update(D_MESG.to_be_bytes());
    hasher.update(c);
    hasher.update(message);
    let digest: [u8; MAX_HASH_LEN] = hasher.finalize().into();
    let q_hash = digest.get(..n).ok_or(INTERNAL)?;
    // Q || Cksm(Q): n + 2 bytes.
    let checksum = cksm(q_hash, ots)?;
    let mut qa_buf = [0u8; MAX_HASH_LEN + 2];
    for (out, byte) in qa_buf.iter_mut().zip(q_hash.iter().chain(checksum.iter())) {
        *out = *byte;
    }
    let qa = qa_buf
        .get(..n.checked_add(2).ok_or(INTERNAL)?)
        .ok_or(INTERNAL)?;

    // Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
    let mut kc = Sha256::new();
    kc.update(id);
    kc.update(q_bytes);
    kc.update(D_PBLC.to_be_bytes());
    let top_digit = max_digit(ots.w)?;
    let mut rest = y;
    for i in 0..ots.p {
        // Pass 1 checked that y is exactly p * n bytes, so this is defensive.
        let y_i = take(&mut rest, n).ok_or(Error::MalformedSignature)?;
        let a = coef(qa, usize::from(i), ots.w).ok_or(INTERNAL)?;
        let mut tmp = [0u8; MAX_HASH_LEN];
        for (out, byte) in tmp.iter_mut().zip(y_i) {
            *out = *byte;
        }
        // for ( j = a; j < 2^w - 1; j = j + 1 )
        //   tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
        for j in a..top_digit {
            let current = tmp.get(..n).ok_or(INTERNAL)?;
            tmp = hash(&[id, &q_bytes, &i.to_be_bytes(), &[j], current], n)?;
        }
        // z[i] = tmp
        kc.update(tmp.get(..n).ok_or(INTERNAL)?);
    }
    // Pass 1 guarantees the length of y, so this is defensive.
    if !rest.is_empty() {
        return Err(Error::MalformedSignature);
    }
    Ok(kc.finalize().into())
}

/// `2^w - 1`, the largest w-bit digit.
fn max_digit(w: u8) -> Result<u8, Error> {
    let top = 1u16.checked_shl(u32::from(w)).ok_or(INTERNAL)?;
    u8::try_from(top.checked_sub(1).ok_or(INTERNAL)?).map_err(|_| INTERNAL)
}

/// SHA-256 of the concatenation of `parts`, keeping the leftmost `len` bytes (24 for
/// SHA-256/192, 32 for SHA-256) at the front of the result; the rest is zeroed.
fn hash(parts: &[&[u8]], len: usize) -> Result<[u8; MAX_HASH_LEN], Error> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest: [u8; MAX_HASH_LEN] = hasher.finalize().into();
    let mut out = [0u8; MAX_HASH_LEN];
    let kept = digest.get(..len).ok_or(INTERNAL)?;
    for (o, b) in out.iter_mut().zip(kept) {
        *o = *b;
    }
    Ok(out)
}

/// `coef(S, i, w)`, RFC 8554 §3.1.3:
/// `(2^w - 1) AND (byte(S, floor(i * w / 8)) >> (8 - (w * (i % (8 / w)) + w)))`.
///
/// `None` if `i` is past the end of `S` or `w` is not 1, 2, 4 or 8.
fn coef(s: &[u8], i: usize, w: u8) -> Option<u8> {
    if !matches!(w, 1 | 2 | 4 | 8) {
        return None;
    }
    let w = usize::from(w);
    let byte = *s.get(i.checked_mul(w)? / 8)?;
    let digits_per_byte = 8usize.checked_div(w)?;
    let position = i.checked_rem(digits_per_byte)?;
    let shift = 8usize.checked_sub(w.checked_mul(position)?.checked_add(w)?)?;
    let mask = 1u16.checked_shl(u32::try_from(w).ok()?)?.checked_sub(1)?;
    let digit = (u16::from(byte) >> shift) & mask;
    u8::try_from(digit).ok()
}

/// `Cksm(S)`, RFC 8554 §4.4 Algorithm 2, as `u16str`:
///
/// ```text
/// sum = 0
/// for ( i = 0; i < (n*8/w); i = i + 1 ) { sum = sum + (2^w - 1) - coef(S, i, w) }
/// return (sum << ls)
/// ```
fn cksm(s: &[u8], ots: &LmotsParams) -> Result<[u8; 2], Error> {
    let top = u32::from(max_digit(ots.w)?);
    let digits = ots
        .n
        .checked_mul(8)
        .and_then(|bits| bits.checked_div(usize::from(ots.w)))
        .ok_or(INTERNAL)?;
    let mut sum: u32 = 0;
    for i in 0..digits {
        let digit = u32::from(coef(s, i, ots.w).ok_or(INTERNAL)?);
        sum = top
            .checked_sub(digit)
            .and_then(|d| sum.checked_add(d))
            .ok_or(INTERNAL)?;
    }
    let shifted = sum.checked_shl(u32::from(ots.ls)).ok_or(INTERNAL)?;
    // "the value sum is a 16-bit unsigned integer"; every tabulated set fits.
    let sum = u16::try_from(shifted).map_err(|_| INTERNAL)?;
    Ok(sum.to_be_bytes())
}

/// A structurally valid HSS public key for tests that never verify with it: `L = 1`,
/// LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, and `I || T[1]` all `fill`.
#[cfg(test)]
#[allow(clippy::indexing_slicing)] // Test-only const fn; the indices are in bounds.
pub(crate) const fn test_public_key(fill: u8) -> [u8; 60] {
    let mut key = [fill; 60];
    let header: [u8; 12] = [0, 0, 0, 1, 0, 0, 0, 0x05, 0, 0, 0, 0x04];
    let mut i = 0;
    while i < header.len() {
        key[i] = header[i];
        i += 1;
    }
    key
}

/// The test signer, for the backend tests (`crate::backend::tests`).
#[cfg(test)]
pub(crate) use tests::{MSG, hss};

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::sync::OnceLock;
    use std::vec;
    use std::vec::Vec;

    use super::*;

    // ---- A minimal test-only signer (RFC 8554 Algorithms 0, 1, 3, 5, 6-generation and
    // 7/8), to produce valid signatures for the structural tests below. It reuses only
    // `coef` and `cksm` from the verifier; the verifier itself is checked against RFC 8554
    // Test Case 1/2, the NIST ACVP vectors and hsslms-signed fixtures in benches/lms-kat.

    struct TestTree {
        lms: LmsParams,
        ots: LmotsParams,
        id: [u8; 16],
        seed: [u8; 32],
        /// Nodes T[1..2^(h+1)), index 0 unused.
        nodes: Vec<Vec<u8>>,
    }

    fn h(parts: &[&[u8]], len: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for p in parts {
            hasher.update(p);
        }
        hasher.finalize()[..len].to_vec()
    }

    impl TestTree {
        fn new(lms_type: u32, ots_type: u32, label: u8) -> Self {
            let lms = lms_params(lms_type).unwrap();
            let ots = lmots_params(ots_type).unwrap();
            let id: [u8; 16] = h(&[b"id", &[label]], 16).try_into().unwrap();
            let seed: [u8; 32] = h(&[b"seed", &[label]], 32).try_into().unwrap();
            let mut tree = Self {
                lms,
                ots,
                id,
                seed,
                nodes: Vec::new(),
            };
            let leaves = 1usize << lms.h;
            let mut nodes = vec![Vec::new(); leaves];
            for r in leaves..2 * leaves {
                let k = tree.ots_public_k((r - leaves) as u32);
                nodes.push(h(
                    &[&id, &(r as u32).to_be_bytes(), &D_LEAF.to_be_bytes(), &k],
                    lms.m,
                ));
            }
            for r in (1..leaves).rev() {
                nodes[r] = h(
                    &[
                        &id,
                        &(r as u32).to_be_bytes(),
                        &D_INTR.to_be_bytes(),
                        &nodes[2 * r],
                        &nodes[2 * r + 1],
                    ],
                    lms.m,
                );
            }
            tree.nodes = nodes;
            tree
        }

        fn x(&self, q: u32, i: u16) -> Vec<u8> {
            h(
                &[
                    &self.id,
                    &q.to_be_bytes(),
                    &i.to_be_bytes(),
                    &[0xff],
                    &self.seed,
                ],
                self.ots.n,
            )
        }

        fn chain(&self, q: u32, i: u16, mut tmp: Vec<u8>, from: u8, to: u8) -> Vec<u8> {
            for j in from..to {
                tmp = h(
                    &[&self.id, &q.to_be_bytes(), &i.to_be_bytes(), &[j], &tmp],
                    self.ots.n,
                );
            }
            tmp
        }

        fn ots_public_k(&self, q: u32) -> Vec<u8> {
            let top = max_digit(self.ots.w).unwrap();
            let mut parts: Vec<Vec<u8>> = Vec::from([
                self.id.to_vec(),
                q.to_be_bytes().to_vec(),
                D_PBLC.to_be_bytes().to_vec(),
            ]);
            for i in 0..self.ots.p {
                parts.push(self.chain(q, i, self.x(q, i), 0, top));
            }
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            h(&refs, self.ots.n)
        }

        fn public_key(&self) -> Vec<u8> {
            let mut pk = Vec::new();
            pk.extend_from_slice(&self.lms.typecode.to_be_bytes());
            pk.extend_from_slice(&self.ots.typecode.to_be_bytes());
            pk.extend_from_slice(&self.id);
            pk.extend_from_slice(&self.nodes[1]);
            pk
        }

        fn sign(&self, q: u32, message: &[u8]) -> Vec<u8> {
            let n = self.ots.n;
            let c = h(&[b"C", &q.to_be_bytes(), message], n);
            let q_hash = h(
                &[
                    &self.id,
                    &q.to_be_bytes(),
                    &D_MESG.to_be_bytes(),
                    &c,
                    message,
                ],
                n,
            );
            let mut qa = q_hash.clone();
            qa.extend_from_slice(&cksm(&q_hash, &self.ots).unwrap());
            let mut sig = Vec::new();
            sig.extend_from_slice(&q.to_be_bytes());
            sig.extend_from_slice(&self.ots.typecode.to_be_bytes());
            sig.extend_from_slice(&c);
            for i in 0..self.ots.p {
                let a = coef(&qa, usize::from(i), self.ots.w).unwrap();
                sig.extend_from_slice(&self.chain(q, i, self.x(q, i), 0, a));
            }
            sig.extend_from_slice(&self.lms.typecode.to_be_bytes());
            let mut r = (1usize << self.lms.h) + q as usize;
            while r > 1 {
                sig.extend_from_slice(&self.nodes[r ^ 1]);
                r >>= 1;
            }
            sig
        }
    }

    pub(crate) const MSG: &[u8] = b"a 32-byte image digest stand-in";

    /// An HSS signature over `MSG` by one tree per `(lms, lmots)` level, each leaf `q`.
    pub(crate) struct Signed {
        pub(crate) pk: Vec<u8>,
        pub(crate) sig: Vec<u8>,
    }

    pub(crate) fn hss(levels: &[(u32, u32)], label: u8) -> Signed {
        let trees: Vec<TestTree> = levels
            .iter()
            .enumerate()
            .map(|(k, &(l, o))| TestTree::new(l, o, label.wrapping_mul(16).wrapping_add(k as u8)))
            .collect();
        let mut pk = (levels.len() as u32).to_be_bytes().to_vec();
        pk.extend_from_slice(&trees[0].public_key());
        let mut sig = ((levels.len() - 1) as u32).to_be_bytes().to_vec();
        for k in 0..trees.len() - 1 {
            sig.extend_from_slice(&trees[k].sign(3, &trees[k + 1].public_key()));
            sig.extend_from_slice(&trees[k + 1].public_key());
        }
        sig.extend_from_slice(&trees.last().unwrap().sign(7, MSG));
        Signed { pk, sig }
    }

    /// HSS L=2, both levels LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
    fn m32_l2() -> &'static Signed {
        static CELL: OnceLock<Signed> = OnceLock::new();
        CELL.get_or_init(|| hss(&[(0x05, 0x04), (0x05, 0x04)], 1))
    }

    /// HSS L=2, both levels LMS_SHA256_M24_H5 / LMOTS_SHA256_N24_W8.
    fn m24_l2() -> &'static Signed {
        static CELL: OnceLock<Signed> = OnceLock::new();
        CELL.get_or_init(|| hss(&[(0x0A, 0x08), (0x0A, 0x08)], 2))
    }

    /// `verify`, i.e. under `ParameterPolicy::keelsign_default()`.
    fn default_verify(pk: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify(pk, MSG, sig)
    }

    fn strict(pk: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify_with_policy(&ParameterPolicy::cnsa_2_0(), pk, MSG, sig)
    }

    fn all_sets(pk: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify_with_policy(&ParameterPolicy::rfc_8554_all_sets(), pk, MSG, sig)
    }

    /// Replace the four bytes at `at` with `value`.
    fn patch_u32(bytes: &[u8], at: usize, value: u32) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out[at..at + 4].copy_from_slice(&value.to_be_bytes());
        out
    }

    /// Length of one LMS signature: `4 + (4 + n * (p + 1)) + 4 + m * h`.
    fn lms_sig_len(n: usize, p: usize, m: usize, h: usize) -> usize {
        4 + 4 + n * (p + 1) + 4 + m * h
    }

    #[test]
    fn signed_two_level_signatures_verify_under_default_and_rfc_policies() {
        for s in [m32_l2(), m24_l2()] {
            assert_eq!(default_verify(&s.pk, &s.sig), Ok(()));
            assert_eq!(all_sets(&s.pk, &s.sig), Ok(()));
            assert_eq!(
                verify(&s.pk, b"another message", &s.sig),
                Err(Error::SignatureInvalid)
            );
        }
        assert_eq!(m32_l2().pk.len(), 60);
        assert_eq!(m24_l2().pk.len(), 52);
        assert_eq!(m32_l2().sig.len(), 4 + 2 * lms_sig_len(32, 34, 32, 5) + 56);
        assert_eq!(m24_l2().sig.len(), 4 + 2 * lms_sig_len(24, 26, 24, 5) + 48);
    }

    #[test]
    fn typecode_tables_match_iana_registry() {
        // IANA "LMS Signatures": 0x05-0x09 LMS_SHA256_M32_H{5,10,15,20,25} (RFC 8554),
        // 0x0A-0x0E LMS_SHA256_M24_H{5,10,15,20,25} (RFC 9858 / SP 800-208 Table 4).
        let lms_expected = [
            (0x05, 32, 5),
            (0x06, 32, 10),
            (0x07, 32, 15),
            (0x08, 32, 20),
            (0x09, 32, 25),
            (0x0A, 24, 5),
            (0x0B, 24, 10),
            (0x0C, 24, 15),
            (0x0D, 24, 20),
            (0x0E, 24, 25),
        ];
        for tc in 0..=0x40u32 {
            let expected = lms_expected.iter().find(|e| e.0 == tc);
            assert_eq!(
                lms_params(tc),
                expected.map(|&(typecode, m, h)| LmsParams { typecode, m, h }),
                "LMS typecode {tc:#x}"
            );
        }
        // IANA "LM-OTS Signatures": 0x01-0x04 LMOTS_SHA256_N32_W{1,2,4,8} (RFC 8554
        // Table 1), 0x05-0x08 LMOTS_SHA256_N24_W{1,2,4,8} (SP 800-208 Table 3).
        let ots_expected = [
            (0x01, 32, 1, 265, 7),
            (0x02, 32, 2, 133, 6),
            (0x03, 32, 4, 67, 4),
            (0x04, 32, 8, 34, 0),
            (0x05, 24, 1, 200, 8),
            (0x06, 24, 2, 101, 6),
            (0x07, 24, 4, 51, 4),
            (0x08, 24, 8, 26, 0),
        ];
        for tc in 0..=0x40u32 {
            let expected = ots_expected.iter().find(|e| e.0 == tc);
            assert_eq!(
                lmots_params(tc),
                expected.map(|&(typecode, n, w, p, ls)| LmotsParams {
                    typecode,
                    n,
                    w,
                    p,
                    ls
                }),
                "LM-OTS typecode {tc:#x}"
            );
        }
        // p and ls from RFC 8554 Appendix B:
        //   u = ceil(8*n/w); v = ceil((floor(lg((2^w - 1) * u)) + 1) / w); ls = 16 - v*w;
        //   p = u + v.
        for &(tc, n, w, p, ls) in &ots_expected {
            let (w, p, ls) = (usize::from(w), usize::from(p), usize::from(ls));
            let u = (8 * n).div_ceil(w);
            let v = ((((1usize << w) - 1) * u).ilog2() as usize + 1).div_ceil(w);
            assert_eq!(p, u + v, "p for {tc:#x}");
            assert_eq!(ls, 16 - v * w, "ls for {tc:#x}");
            // RFC 8554 Table 1 sig_len = 4 + n * (p + 1).
            let sig_len = 4 + n * (p + 1);
            if n == 32 {
                assert_eq!(
                    sig_len,
                    [8516, 4292, 2180, 1124][w.trailing_zeros() as usize]
                );
            }
        }
        // Domain separation (RFC 8554 §7.1) and the public-key lengths.
        assert_eq!(
            [D_PBLC, D_MESG, D_LEAF, D_INTR],
            [0x8080, 0x8181, 0x8282, 0x8383]
        );
        assert_eq!(PUBLIC_KEY_LENS, [4 + 4 + 4 + 16 + 24, 4 + 4 + 4 + 16 + 32]);
        assert_eq!(MAX_HSS_LEVELS, 2);
        assert_eq!(ParameterPolicy::keelsign_default().max_levels(), 2);
        assert_eq!(ParameterPolicy::cnsa_2_0().max_levels(), 1);
        assert_eq!(ParameterPolicy::rfc_8554_all_sets().max_levels(), 8);
    }

    #[test]
    fn coef_and_cksm_match_rfc_8554() {
        // RFC 8554 §3.1.3: "if S is the string 0x1234, then coef(S, 7, 1) is 0 and
        // coef(S, 0, 4) is 1."
        let s = [0x12, 0x34];
        assert_eq!(coef(&s, 7, 1), Some(0));
        assert_eq!(coef(&s, 0, 4), Some(1));
        let bits: Vec<u8> = (0..16).map(|i| coef(&s, i, 1).unwrap()).collect();
        assert_eq!(bits, [0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0]);
        let nibbles: Vec<u8> = (0..4).map(|i| coef(&s, i, 4).unwrap()).collect();
        assert_eq!(nibbles, [1, 2, 3, 4]);
        let pairs: Vec<u8> = (0..8).map(|i| coef(&s, i, 2).unwrap()).collect();
        assert_eq!(pairs, [0, 1, 0, 2, 0, 3, 1, 0]);
        assert_eq!(coef(&s, 1, 8), Some(0x34));
        assert_eq!(coef(&s, 2, 8), None, "past the end");
        assert_eq!(coef(&s, 0, 3), None, "w must be 1, 2, 4 or 8");

        // Cksm of an all-zero Q is the maximum sum, shifted by ls; of an all-ones Q is 0.
        for tc in 1..=8 {
            let ots = lmots_params(tc).unwrap();
            let zero = [0u8; 32];
            let digits = (ots.n * 8) as u32 / u32::from(ots.w);
            let max = ((1u32 << ots.w) - 1) * digits;
            assert_eq!(
                cksm(&zero[..ots.n], &ots),
                Ok(((max << ots.ls) as u16).to_be_bytes()),
                "{tc}"
            );
            let ones = [0xffu8; 32];
            assert_eq!(cksm(&ones[..ots.n], &ots), Ok([0, 0]), "{tc}");
            // The checksum digits used by coef (p - u of them) cover every set bit.
            let u = (ots.n * 8).div_ceil(usize::from(ots.w));
            let used_bits = (usize::from(ots.p) - u) * usize::from(ots.w);
            assert!((max << ots.ls) >> (16 - used_bits) << (16 - used_bits) == max << ots.ls);
        }
    }

    /// An HSS public key with `L = levels` and a well-formed key shape for the pair (m
    /// from the LMS set, else 32).
    fn shaped_key(levels: u32, lms: u32, ots: u32) -> Vec<u8> {
        let m = lms_params(lms).map_or(32, |p| p.m);
        let mut pk = levels.to_be_bytes().to_vec();
        pk.extend_from_slice(&lms.to_be_bytes());
        pk.extend_from_slice(&ots.to_be_bytes());
        pk.extend_from_slice(&[0x5a; 16]);
        pk.extend_from_slice(&vec![0xa5; m]);
        pk
    }

    /// `Nspk = 0` followed by the bottom (M32 H5 W8) LMS signature of `m32_l2()`.
    fn one_level_dummy_signature() -> Vec<u8> {
        let one_level_sig = &m32_l2().sig[4 + lms_sig_len(32, 34, 32, 5) + 56..];
        let mut sig = 0u32.to_be_bytes().to_vec();
        sig.extend_from_slice(one_level_sig);
        sig
    }

    #[test]
    fn every_typecode_pair_and_level_count_matches_each_policy() {
        // The expected sets, written independently of `ParameterPolicy`: the two device
        // policies accept the W8 pairs (SHA-65's set), the RFC policy every `m == n` pair
        // of the SHA-256 families; at most 2 / 1 / 8 levels.
        fn w8_pair(lms: u32, ots: u32) -> bool {
            matches!((lms, ots), (0x05..=0x09, 0x04) | (0x0A..=0x0E, 0x08))
        }
        fn m_eq_n_pair(lms: u32, ots: u32) -> bool {
            matches!(
                (lms, ots),
                (0x05..=0x09, 0x01..=0x04) | (0x0A..=0x0E, 0x05..=0x08)
            )
        }
        type Pair = fn(u32, u32) -> bool;
        let policies: [(&str, ParameterPolicy, Pair, u32); 3] = [
            (
                "keelsign_default",
                ParameterPolicy::keelsign_default(),
                w8_pair,
                2,
            ),
            ("cnsa_2_0", ParameterPolicy::cnsa_2_0(), w8_pair, 1),
            (
                "rfc_8554_all_sets",
                ParameterPolicy::rfc_8554_all_sets(),
                m_eq_n_pair,
                8,
            ),
        ];
        let sig = one_level_dummy_signature();
        let level_counts = [0u32, 1, 2, 3, 4, 8, 9, u32::MAX];
        let mut accepted_pairs = [0usize; 3];
        for lms in 0..=0x20u32 {
            for ots in 0..=0x10u32 {
                for (k, (name, policy, pair, max_levels)) in policies.iter().enumerate() {
                    assert_eq!(policy.max_levels(), *max_levels, "{name}");
                    assert_eq!(
                        policy.allows(lms, ots),
                        pair(lms, ots),
                        "{name} {lms:#x}/{ots:#x}"
                    );
                    if pair(lms, ots) {
                        accepted_pairs[k] += 1;
                    }
                    for levels in level_counts {
                        let pk = shaped_key(levels, lms, ots);
                        let result = verify_with_policy(policy, &pk, MSG, &sig);
                        let in_policy = pair(lms, ots) && (1..=*max_levels).contains(&levels);
                        if in_policy {
                            // Past the policy gate: the one-level signature is either the
                            // wrong shape for this key (`Nspk + 1 != L`, other lengths) or
                            // does not verify under it.
                            assert!(
                                matches!(
                                    result,
                                    Err(Error::MalformedSignature | Error::SignatureInvalid)
                                ),
                                "{name} {lms:#x}/{ots:#x} L={levels}: {result:?}"
                            );
                        } else {
                            assert_eq!(
                                result,
                                Err(Error::UnsupportedParameterSet),
                                "{name} {lms:#x}/{ots:#x} L={levels}"
                            );
                        }
                    }
                }
                // cnsa_2_0 ⊆ keelsign_default ⊆ rfc_8554_all_sets on every cell.
                let [default, cnsa, rfc] = policies.each_ref().map(|(_, p, _, _)| *p);
                assert!(!cnsa.allows(lms, ots) || default.allows(lms, ots));
                assert!(!default.allows(lms, ots) || rfc.allows(lms, ots));
                for levels in level_counts {
                    let accepts = |p: &ParameterPolicy| {
                        p.allows(lms, ots) && (1..=p.max_levels()).contains(&levels)
                    };
                    assert!(!accepts(&cnsa) || accepts(&default), "{lms:#x}/{ots:#x}");
                    assert!(!accepts(&default) || accepts(&rfc), "{lms:#x}/{ots:#x}");
                }
                // The independent tables agree with each other: W8 pairs are m == n pairs.
                assert!(!w8_pair(lms, ots) || m_eq_n_pair(lms, ots));
                // m != n is unsupported under every policy.
                if let (Some(l), Some(o)) = (lms_params(lms), lmots_params(ots)) {
                    assert_eq!(l.m == o.n, m_eq_n_pair(lms, ots), "{lms:#x}/{ots:#x}");
                }
            }
        }
        // Every height H5-H25 of both hashes: W8 only for the device policies, W1-W8 for
        // the RFC policy.
        assert_eq!(accepted_pairs, [10, 10, 40]);

        // The gate covers the level-1 key signed inside the signature, before any hash:
        // with a level-1 key outside the default policy the result is unsupported even
        // though level 0's signature no longer matches.
        let good = m32_l2();
        let child_at = 4 + lms_sig_len(32, 34, 32, 5);
        for (lms, ots) in [
            (0x05, 0x03),
            (0x05, 0x01),
            (0x0A, 0x08),
            (0x0F, 0x0C),
            (0x05, 0x09),
            (0x19, 0x04),
        ] {
            let sig = patch_u32(&patch_u32(&good.sig, child_at, lms), child_at + 4, ots);
            assert_eq!(
                default_verify(&good.pk, &sig),
                Err(Error::UnsupportedParameterSet),
                "{lms:#x}/{ots:#x}"
            );
            // Under cnsa_2_0 the L = 2 key is refused first.
            assert_eq!(
                strict(&good.pk, &sig),
                Err(Error::UnsupportedParameterSet),
                "{lms:#x}/{ots:#x}"
            );
        }
        // A level-1 key with the other hash (M24 under an M32 level 0) is unsupported
        // under every policy (SP 800-208 §4), even at the right length.
        let mut mixed = good.sig[..child_at].to_vec();
        mixed.extend_from_slice(&0x0Au32.to_be_bytes());
        mixed.extend_from_slice(&0x08u32.to_be_bytes());
        mixed.extend_from_slice(&good.sig[child_at + 8..]);
        assert_eq!(
            default_verify(&good.pk, &mixed),
            Err(Error::UnsupportedParameterSet)
        );
        assert_eq!(
            all_sets(&good.pk, &mixed),
            Err(Error::UnsupportedParameterSet)
        );
    }

    #[test]
    fn two_level_signatures_are_unsupported_under_cnsa_2_0_and_single_tree_w8_verifies_for_both_hashes()
     {
        // L = 1, H5, both hash sizes: accepted under all three policies.
        for (s, pk_len) in [(hss(&[(0x05, 0x04)], 4), 60), (hss(&[(0x0A, 0x08)], 5), 52)] {
            assert_eq!(s.pk.len(), pk_len);
            assert_eq!(&s.pk[..4], &1u32.to_be_bytes());
            assert_eq!(default_verify(&s.pk, &s.sig), Ok(()));
            assert_eq!(strict(&s.pk, &s.sig), Ok(()));
            assert_eq!(all_sets(&s.pk, &s.sig), Ok(()));
            assert_eq!(
                verify_with_policy(&ParameterPolicy::cnsa_2_0(), &s.pk, b"other", &s.sig),
                Err(Error::SignatureInvalid)
            );
        }
        // L = 2, both hash sizes: valid signatures under the default and RFC policies,
        // unsupported under cnsa_2_0 whatever the signature bytes are (the key is refused
        // before the signature is read).
        for s in [m32_l2(), m24_l2()] {
            assert_eq!(&s.pk[..4], &2u32.to_be_bytes());
            assert_eq!(default_verify(&s.pk, &s.sig), Ok(()));
            assert_eq!(all_sets(&s.pk, &s.sig), Ok(()));
            assert_eq!(strict(&s.pk, &s.sig), Err(Error::UnsupportedParameterSet));
            for sig in [&[][..], &s.sig[..10], &[0xA5; 3000][..]] {
                assert_eq!(strict(&s.pk, sig), Err(Error::UnsupportedParameterSet));
            }
        }
        // An L = 1 key with an Nspk = 1 (two-level) signature is malformed under all three.
        for s in [m32_l2(), m24_l2()] {
            let pk = patch_u32(&s.pk, 0, 1);
            assert_eq!(default_verify(&pk, &s.sig), Err(Error::MalformedSignature));
            assert_eq!(strict(&pk, &s.sig), Err(Error::MalformedSignature));
            assert_eq!(all_sets(&pk, &s.sig), Err(Error::MalformedSignature));
        }
    }

    #[test]
    fn keelsign_default_is_sha_65s_accepted_set() {
        let policy = ParameterPolicy::keelsign_default();
        // SHA-65's policy, field for field.
        assert_eq!(
            policy,
            ParameterPolicy {
                sets: Sets::W8,
                max_levels: 2
            }
        );
        assert_eq!(policy.max_levels(), 2);
        assert_eq!(policy.max_levels(), MAX_HSS_LEVELS);
        // Exactly the ten W8 pairs, each at L = 1 and L = 2, and no L = 3.
        let w8: Vec<(u32, u32)> = (0x05..=0x09)
            .map(|l| (l, 0x04))
            .chain((0x0A..=0x0E).map(|l| (l, 0x08)))
            .collect();
        assert_eq!(w8.len(), 10);
        let sig = one_level_dummy_signature();
        for lms in 0..=0x20u32 {
            for ots in 0..=0x10u32 {
                let expected = w8.contains(&(lms, ots));
                assert_eq!(policy.allows(lms, ots), expected, "{lms:#x}/{ots:#x}");
                if expected {
                    for levels in [1u32, 2] {
                        let pk = shaped_key(levels, lms, ots);
                        assert_ne!(
                            verify_with_policy(&policy, &pk, MSG, &sig),
                            Err(Error::UnsupportedParameterSet),
                            "{lms:#x}/{ots:#x} L={levels}"
                        );
                    }
                    let pk = shaped_key(3, lms, ots);
                    assert_eq!(
                        verify_with_policy(&policy, &pk, MSG, &sig),
                        Err(Error::UnsupportedParameterSet)
                    );
                }
            }
        }
        // `verify` is `verify_with_policy(&keelsign_default(), ..)` on the signed cases.
        let one = hss(&[(0x0A, 0x08)], 3);
        for s in [m32_l2(), m24_l2(), &one] {
            assert_eq!(
                verify(&s.pk, MSG, &s.sig),
                verify_with_policy(&policy, &s.pk, MSG, &s.sig)
            );
            assert_eq!(verify(&s.pk, MSG, &s.sig), Ok(()));
            assert_eq!(
                verify(&s.pk, b"other", &s.sig),
                verify_with_policy(&policy, &s.pk, b"other", &s.sig)
            );
        }
        // The device backend's default is the same policy.
        assert_eq!(crate::DefaultBackend::new().lms_policy(), policy);
    }

    #[test]
    fn every_truncation_of_a_valid_signature_is_malformed_not_a_panic() {
        for s in [m32_l2(), m24_l2()] {
            for len in 0..s.sig.len() {
                assert_eq!(
                    default_verify(&s.pk, &s.sig[..len]),
                    Err(Error::MalformedSignature),
                    "truncated to {len} of {}",
                    s.sig.len()
                );
            }
            // One trailing byte, or many.
            for extra in [1usize, 2, 32, 1000] {
                let mut long = s.sig.clone();
                long.extend(std::iter::repeat_n(0u8, extra));
                assert_eq!(
                    default_verify(&s.pk, &long),
                    Err(Error::MalformedSignature),
                    "+{extra}"
                );
            }
            // Nspk + 1 != L.
            for nspk in [0u32, 2, 7, u32::MAX] {
                let sig = patch_u32(&s.sig, 0, nspk);
                assert_eq!(
                    default_verify(&s.pk, &sig),
                    Err(Error::MalformedSignature),
                    "Nspk={nspk}"
                );
            }
        }
        assert_eq!(
            default_verify(&m32_l2().pk, &[]),
            Err(Error::MalformedSignature)
        );
    }

    #[test]
    fn wrong_length_public_key_is_invalid_public_key() {
        for s in [m32_l2(), m24_l2()] {
            // Too short to hold L and both typecodes.
            for len in 0..12 {
                assert_eq!(
                    default_verify(&s.pk[..len], &s.sig),
                    Err(Error::InvalidPublicKey),
                    "{len}"
                );
            }
            // Typecodes present but the wrong length for them.
            for len in 12..s.pk.len() {
                assert_eq!(
                    default_verify(&s.pk[..len], &s.sig),
                    Err(Error::InvalidPublicKey),
                    "{len}"
                );
            }
            let mut long = s.pk.clone();
            long.push(0);
            assert_eq!(default_verify(&long, &s.sig), Err(Error::InvalidPublicKey));
        }
        // An M32 key cut to the M24 length (52 bytes) and an M24 key padded to 60.
        assert_eq!(
            default_verify(&m32_l2().pk[..52], &m32_l2().sig),
            Err(Error::InvalidPublicKey)
        );
        let mut padded = m24_l2().pk.clone();
        padded.extend_from_slice(&[0; 8]);
        assert_eq!(
            default_verify(&padded, &m24_l2().sig),
            Err(Error::InvalidPublicKey)
        );
    }

    #[test]
    fn signature_typecode_mismatch_and_q_out_of_range_are_signature_invalid() {
        let s = m32_l2();
        let bottom = 4 + lms_sig_len(32, 34, 32, 5) + 56;
        // Level-0 and level-1 LM-OTS typecode (Algorithm 6a step 2c), with a length-
        // compatible and an unknown value.
        for at in [4 + 4, bottom + 4] {
            for tc in [0x03u32, 0x08, 0x01, 0xffff_ffff] {
                assert_eq!(
                    default_verify(&s.pk, &patch_u32(&s.sig, at, tc)),
                    Err(Error::SignatureInvalid)
                );
            }
        }
        // LMS typecode inside the signature (step 2g).
        for at in [4 + 4 + 32 * 35, bottom + 4 + 32 * 35] {
            for tc in [0x06u32, 0x0A, 0x09, 0] {
                assert_eq!(
                    default_verify(&s.pk, &patch_u32(&s.sig, at, tc)),
                    Err(Error::SignatureInvalid)
                );
            }
        }
        // q >= 2^h (step 2i) at either level, and a different leaf q < 2^h.
        for at in [4, bottom] {
            for q in [32u32, 33, 1 << 25, u32::MAX, 0, 31] {
                assert_eq!(
                    default_verify(&s.pk, &patch_u32(&s.sig, at, q)),
                    Err(Error::SignatureInvalid),
                    "q={q}"
                );
            }
        }
        // Single-bit flips across the M24 signature are all rejected, never a panic.
        // Flips in hashed fields are `SignatureInvalid`; flips in the level-1 key's
        // typecodes can change its parameter set (unsupported or a different length).
        let s = m24_l2();
        for at in (4..s.sig.len()).step_by(7) {
            let mut sig = s.sig.clone();
            sig[at] ^= 0x01;
            let result = default_verify(&s.pk, &sig);
            assert!(result.is_err(), "flip at {at} verified");
        }
        // Flipping the public key's root or I also fails.
        for at in [12, 30, 51] {
            let mut pk = s.pk.clone();
            pk[at] ^= 0x80;
            assert_eq!(
                default_verify(&pk, &s.sig),
                Err(Error::SignatureInvalid),
                "pk flip at {at}"
            );
        }
    }

    #[test]
    fn single_level_and_all_heights_are_accepted() {
        // L = 1 (a plain LMS key) verifies under all three policies.
        let one = hss(&[(0x0A, 0x08)], 3);
        assert_eq!(default_verify(&one.pk, &one.sig), Ok(()));
        assert_eq!(strict(&one.pk, &one.sig), Ok(()));
        assert_eq!(all_sets(&one.pk, &one.sig), Ok(()));
        // Every height H5-H25 of both hashes is inside every policy; the signature
        // length for each follows RFC 8554 Algorithm 6a step 2i.
        for (lms, ots) in [(0x05..=0x09, 0x04), (0x0A..=0x0E, 0x08)] {
            for tc in lms {
                assert!(ParameterPolicy::keelsign_default().allows(tc, ots));
                assert!(ParameterPolicy::cnsa_2_0().allows(tc, ots));
                assert!(ParameterPolicy::rfc_8554_all_sets().allows(tc, ots));
                let l = lms_params(tc).unwrap();
                let o = lmots_params(ots).unwrap();
                let pk = [0u8; 60];
                let key = LmsPublicKey {
                    lms: l,
                    ots: o,
                    id: &pk[..16],
                    root: &pk[..l.m],
                };
                let len = lms_sig_len(o.n, usize::from(o.p), l.m, usize::from(l.h));
                let sig = vec![0u8; len];
                let mut rest = sig.as_slice();
                assert!(parse_lms_signature(&key, &mut rest).is_ok());
                assert!(rest.is_empty());
                let mut short = &sig[..len - 1];
                assert_eq!(
                    parse_lms_signature(&key, &mut short).err(),
                    Some(Error::MalformedSignature)
                );
            }
        }
    }
}
