//! MCUboot image header and TLV-area parser.
//!
//! Parses an MCUboot image as `imgtool` writes it (and as keelsign extends it,
//! [docs/image-format.md][spec]): the 32-byte image header, the image body, the optional
//! protected TLV area and the unprotected TLV area. Layout and constants are MCUboot's,
//! cited at commit `a8ffd2c` (`boot/bootutil/include/bootutil/image.h`):
//!
//! ```text
//! 0                 hdr_size          tlv_offset         hashed_len                 tlv_end
//! | header (32 B)…  | body (img_size) | protected area   | unprotected area         | trailer…
//!                                     | 0x6908, tlv_tot  | 0x6907, tlv_tot, TLVs…   |
//! ```
//!
//! [`Image::parse`] validates everything once, before exposing anything: the header, both
//! TLV info headers and every TLV header in both areas, against the input's bounds. After
//! that, iterating the TLVs ([`TlvArea::iter`], [`TlvArea::pairs`], [`Image::tlvs`])
//! cannot fail, and `image.unprotected().pairs()` feeds
//! [`select_pq_signature`](crate::select_pq_signature) and [`verify_pq`](crate::verify_pq)
//! directly. The parser reads the input only through bounds-checked slicing and checked
//! arithmetic; every malformed input is a [`ParseError`].
//!
//! # Post-quantum signature selection
//!
//! PQ selection MUST use the unprotected area only: `image.unprotected().pairs()`, never
//! [`Image::tlvs`] or the protected area's pairs. keelsign TLVs are unprotected-only
//! ([docs/image-format.md][spec]), so keelsign TLVs in the protected area are ignored for
//! PQ selection: a PQ signature TLV there is inside `M`, the bytes it would sign, so it can
//! never be a valid signature over `M`. The parser still yields them (from
//! [`Image::protected`] and [`Image::tlvs`]); rejecting such images outright is a candidate
//! image-policy rule (SHA-46).
//!
//! # What the parser does not decide
//!
//! - **Unknown TLV types are yielded, never errors**, in both areas: MCUboot and keelsign
//!   TLVs get a [`TlvKind`], the reserved keelsign IDs `0x4BA4..=0x4BAF` are
//!   [`TlvKind::KeelsignReserved`] and everything else is [`TlvKind::Unknown`]. The
//!   ticket (SHA-35) asked for an `UnknownTlv` error; the image format (SHA-37) requires
//!   verifiers to ignore unknown TLV types, and that constraint wins.
//! - The header flags, how many `SHA256` TLVs an image has, the KEYHASH / signature
//!   pairing and anti-rollback are image policy (SHA-46). The parser only exposes them
//!   ([`Header::flags`], [`Image::tlvs`]).
//! - The order of TLVs carries no meaning: no state is kept from one TLV to the next.
//!
//! # Rules
//!
//! - Little-endian images only. A big-endian image fails the magic check
//!   ([`ParseError::BadMagic`]).
//! - Three rules are intentionally stricter than MCUboot:
//!   - a header size below [`IMAGE_HEADER_SIZE`] is [`ParseError::HeaderTooSmall`];
//!   - a TLV info header with `tlv_tot < 4` (smaller than itself) is
//!     [`ParseError::LengthMismatch`];
//!   - the protected TLVs must tile the protected area exactly, ending at `prot_end`
//!     (`hdr_size + img_size + protect_tlv_size`): a protected TLV whose header or value
//!     runs past `prot_end`, or 1–3 bytes left over before it, is
//!     [`ParseError::LengthMismatch`]. MCUboot `a8ffd2c`'s `bootutil_tlv_iter_next` bounds
//!     each TLV by `end = it->prot ? it->prot_end : it->tlv_end` (`tlv.c:151`, checked at
//!     `:163-164` and `:179`), and `bootutil_img_validate` walks with `IMAGE_TLV_ANY` and
//!     `prot = false` (`image_validate.c:285`), so there protected TLVs are bounded only by
//!     `tlv_end`; the unprotected info header is skipped only when a TLV ends exactly at
//!     `prot_end` (`tlv.c:133-142`). Such an image can be accepted by MCUboot.
//! - A post-quantum signature TLV (`0x4BA1..=0x4BA3`) longer than
//!   [`MAX_PQ_SIGNATURE_LEN`] is [`ParseError::PqSignatureTooLong`], in either area.
//! - Bytes after the unprotected TLV area (a padded slot's trailer) are allowed;
//!   [`Image::tlv_end`] says where the image ends.
//!
//! [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md

use core::fmt;
use core::ops::Range;

use crate::algorithm::Algorithm;
use crate::tlv::{
    KEELSIGN_TLV_RANGE, MAX_PQ_SIGNATURE_LEN, TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG,
    TLV_MLDSA44_SIG, TLV_MLDSA65_SIG,
};

/// `IMAGE_MAGIC`, the first header field (`image.h:49`).
pub const IMAGE_MAGIC: u32 = 0x96F3_B83D;
/// `IMAGE_HEADER_SIZE`: the size of `struct image_header` (`image.h:55`, `:167-176`).
pub const IMAGE_HEADER_SIZE: usize = 32;
/// `IMAGE_TLV_INFO_MAGIC`, the unprotected TLV area's info magic (`image.h:52`).
pub const TLV_INFO_MAGIC: u16 = 0x6907;
/// `IMAGE_TLV_PROT_INFO_MAGIC`, the protected TLV area's info magic (`image.h:53`).
pub const TLV_PROT_INFO_MAGIC: u16 = 0x6908;
/// Size of `struct image_tlv_info` (`u16 magic, u16 tlv_tot`, `image.h:179-182`).
pub const TLV_INFO_SIZE: usize = 4;
/// Size of `struct image_tlv` (`u16 type, u16 len`, `image.h:185-188`).
pub const TLV_HEADER_SIZE: usize = 4;

/// `IMAGE_TLV_KEYHASH`: hash of the public key (`image.h:99`).
pub const IMAGE_TLV_KEYHASH: u16 = 0x01;
/// `IMAGE_TLV_PUBKEY`: the public key (`image.h:100`).
pub const IMAGE_TLV_PUBKEY: u16 = 0x02;
/// `IMAGE_TLV_SHA256`: SHA-256 of header, body and protected TLVs (`image.h:101`).
pub const IMAGE_TLV_SHA256: u16 = 0x10;
/// `IMAGE_TLV_SHA384` (`image.h:102`).
pub const IMAGE_TLV_SHA384: u16 = 0x11;
/// `IMAGE_TLV_SHA512` (`image.h:103`).
pub const IMAGE_TLV_SHA512: u16 = 0x12;
/// `IMAGE_TLV_RSA2048_PSS` (`image.h:104`).
pub const IMAGE_TLV_RSA2048_PSS: u16 = 0x20;
/// `IMAGE_TLV_ECDSA_SIG` (`image.h:106`).
pub const IMAGE_TLV_ECDSA_SIG: u16 = 0x22;
/// `IMAGE_TLV_RSA3072_PSS` (`image.h:107`).
pub const IMAGE_TLV_RSA3072_PSS: u16 = 0x23;
/// `IMAGE_TLV_ED25519` (`image.h:108`).
pub const IMAGE_TLV_ED25519: u16 = 0x24;
/// `IMAGE_TLV_SIG_PURE`: the signature is over the image, not its digest (`image.h:109`).
pub const IMAGE_TLV_SIG_PURE: u16 = 0x25;
/// `IMAGE_TLV_DEPENDENCY` (`image.h:119`).
pub const IMAGE_TLV_DEPENDENCY: u16 = 0x40;
/// `IMAGE_TLV_SEC_CNT`: the security counter (`image.h:120`).
pub const IMAGE_TLV_SEC_CNT: u16 = 0x50;
/// `IMAGE_TLV_BOOT_RECORD`: the measured boot record (`image.h:121`).
pub const IMAGE_TLV_BOOT_RECORD: u16 = 0x60;

/// `IMAGE_F_PIC` (`image.h:61`).
pub const IMAGE_F_PIC: u32 = 0x0000_0001;
/// `IMAGE_F_ENCRYPTED_AES128` (`image.h:62`).
pub const IMAGE_F_ENCRYPTED_AES128: u32 = 0x0000_0004;
/// `IMAGE_F_ENCRYPTED_AES256` (`image.h:63`).
pub const IMAGE_F_ENCRYPTED_AES256: u32 = 0x0000_0008;
/// `IMAGE_F_NON_BOOTABLE` (`image.h:64`).
pub const IMAGE_F_NON_BOOTABLE: u32 = 0x0000_0010;
/// `IMAGE_F_RAM_LOAD` (`image.h:70`).
pub const IMAGE_F_RAM_LOAD: u32 = 0x0000_0020;
/// `IMAGE_F_ROM_FIXED` (`image.h:76`).
pub const IMAGE_F_ROM_FIXED: u32 = 0x0000_0100;
/// `IMAGE_F_COMPRESSED_LZMA1` (`image.h:81`).
pub const IMAGE_F_COMPRESSED_LZMA1: u32 = 0x0000_0200;
/// `IMAGE_F_COMPRESSED_LZMA2` (`image.h:82`).
pub const IMAGE_F_COMPRESSED_LZMA2: u32 = 0x0000_0400;
/// `IMAGE_F_COMPRESSED_ARM_THUMB_FLT` (`image.h:83`).
pub const IMAGE_F_COMPRESSED_ARM_THUMB_FLT: u32 = 0x0000_0800;

const ENCRYPTION_FLAGS: u32 = IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_ENCRYPTED_AES256;
const COMPRESSION_FLAGS: u32 =
    IMAGE_F_COMPRESSED_LZMA1 | IMAGE_F_COMPRESSED_LZMA2 | IMAGE_F_COMPRESSED_ARM_THUMB_FLT;
const KNOWN_FLAGS: u32 = IMAGE_F_PIC
    | ENCRYPTION_FLAGS
    | IMAGE_F_NON_BOOTABLE
    | IMAGE_F_RAM_LOAD
    | IMAGE_F_ROM_FIXED
    | COMPRESSION_FLAGS;

/// Why an image could not be parsed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The header magic is not [`IMAGE_MAGIC`] read little-endian (big-endian images
    /// included).
    BadMagic,
    /// The input ends before the header, the body or a TLV area does.
    Truncated,
    /// The header's `hdr_size` is below [`IMAGE_HEADER_SIZE`] (stricter than MCUboot).
    HeaderTooSmall,
    /// `hdr_size + img_size + protect_tlv_size` (or the TLV area end) overflows `u32`, or
    /// an offset does not fit `usize`.
    SizeOverflow,
    /// A TLV info header has the wrong magic: not [`TLV_PROT_INFO_MAGIC`] where the header
    /// announces a protected area, or not [`TLV_INFO_MAGIC`] for the unprotected area.
    BadTlvInfoMagic,
    /// The protected area's `tlv_tot` differs from the header's `protect_tlv_size`, or the
    /// header announces no protected area but one is there.
    ProtectedSizeMismatch,
    /// A TLV area's `tlv_tot` is below [`TLV_INFO_SIZE`], or a TLV header or value runs
    /// past the end of its area.
    LengthMismatch,
    /// A post-quantum signature TLV is longer than [`MAX_PQ_SIGNATURE_LEN`].
    PqSignatureTooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::BadMagic => "not a little-endian MCUboot image (bad header magic)",
            ParseError::Truncated => "image is truncated",
            ParseError::HeaderTooSmall => "image header size is below 32 bytes",
            ParseError::SizeOverflow => "image sizes overflow",
            ParseError::BadTlvInfoMagic => "TLV info header has the wrong magic",
            ParseError::ProtectedSizeMismatch => {
                "protected TLV area size does not match the image header"
            }
            ParseError::LengthMismatch => "TLV length runs past its area",
            ParseError::PqSignatureTooLong => "post-quantum signature TLV is too long",
        })
    }
}

impl core::error::Error for ParseError {}

/// `struct image_version`: `major.minor.revision+build_num`.
///
/// It deliberately has no ordering: comparing versions (anti-rollback) is policy
/// (SHA-46).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageVersion {
    /// `iv_major`.
    pub major: u8,
    /// `iv_minor`.
    pub minor: u8,
    /// `iv_revision`.
    pub revision: u16,
    /// `iv_build_num`.
    pub build_num: u32,
}

/// The header's `ih_flags` (`IMAGE_F_*`), exposed but not acted on (SHA-46).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageFlags(pub u32);

impl ImageFlags {
    /// `IMAGE_F_ENCRYPTED_AES128` or `IMAGE_F_ENCRYPTED_AES256` is set (MCUboot's
    /// `IS_ENCRYPTED`, `image.h:191-192`).
    pub fn is_encrypted(self) -> bool {
        self.0 & ENCRYPTION_FLAGS != 0
    }

    /// Any `IMAGE_F_COMPRESSED_*` flag is set (MCUboot's `IS_COMPRESSED`,
    /// `image.h:196-198`).
    pub fn is_compressed(self) -> bool {
        self.0 & COMPRESSION_FLAGS != 0
    }

    /// `IMAGE_F_NON_BOOTABLE` is set.
    pub fn non_bootable(self) -> bool {
        self.0 & IMAGE_F_NON_BOOTABLE != 0
    }

    /// `IMAGE_F_RAM_LOAD` is set.
    pub fn ram_load(self) -> bool {
        self.0 & IMAGE_F_RAM_LOAD != 0
    }

    /// `IMAGE_F_ROM_FIXED` is set.
    pub fn rom_fixed(self) -> bool {
        self.0 & IMAGE_F_ROM_FIXED != 0
    }

    /// The set bits that are not an `IMAGE_F_*` flag MCUboot defines.
    pub fn unknown_bits(self) -> u32 {
        self.0 & !KNOWN_FLAGS
    }
}

/// The MCUboot image header (`struct image_header`, `image.h:167-176`), without its magic
/// and padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// `ih_load_addr`.
    pub load_addr: u32,
    /// `ih_hdr_size`: bytes from the start of the image to the body, at least
    /// [`IMAGE_HEADER_SIZE`].
    pub hdr_size: u16,
    /// `ih_protect_tlv_size`: size of the protected TLV area, its info header included;
    /// `0` if there is none.
    pub protect_tlv_size: u16,
    /// `ih_img_size`: size of the body.
    pub img_size: u32,
    /// `ih_flags`.
    pub flags: ImageFlags,
    /// `ih_ver`.
    pub version: ImageVersion,
}

impl Header {
    /// Parse the header from the first [`IMAGE_HEADER_SIZE`] bytes of `bytes`; any further
    /// bytes are ignored.
    ///
    /// Errors: [`ParseError::Truncated`] if `bytes` is shorter than the header,
    /// [`ParseError::BadMagic`], then [`ParseError::HeaderTooSmall`].
    pub fn parse(bytes: &[u8]) -> Result<Header, ParseError> {
        let (raw, _) = bytes
            .split_first_chunk::<IMAGE_HEADER_SIZE>()
            .ok_or(ParseError::Truncated)?;
        let [
            m0,
            m1,
            m2,
            m3,
            a0,
            a1,
            a2,
            a3,
            h0,
            h1,
            p0,
            p1,
            i0,
            i1,
            i2,
            i3,
            f0,
            f1,
            f2,
            f3,
            major,
            minor,
            r0,
            r1,
            b0,
            b1,
            b2,
            b3,
            _,
            _,
            _,
            _,
        ] = *raw;
        if u32::from_le_bytes([m0, m1, m2, m3]) != IMAGE_MAGIC {
            return Err(ParseError::BadMagic);
        }
        let hdr_size = u16::from_le_bytes([h0, h1]);
        if usize::from(hdr_size) < IMAGE_HEADER_SIZE {
            return Err(ParseError::HeaderTooSmall);
        }
        Ok(Header {
            load_addr: u32::from_le_bytes([a0, a1, a2, a3]),
            hdr_size,
            protect_tlv_size: u16::from_le_bytes([p0, p1]),
            img_size: u32::from_le_bytes([i0, i1, i2, i3]),
            flags: ImageFlags(u32::from_le_bytes([f0, f1, f2, f3])),
            version: ImageVersion {
                major,
                minor,
                revision: u16::from_le_bytes([r0, r1]),
                build_num: u32::from_le_bytes([b0, b1, b2, b3]),
            },
        })
    }

    /// Offset of the first TLV area: `hdr_size + img_size` (MCUboot's `BOOT_TLV_OFF`,
    /// `bootutil_priv.h:479`), or [`ParseError::SizeOverflow`].
    pub fn tlv_offset(&self) -> Result<u32, ParseError> {
        u32::from(self.hdr_size)
            .checked_add(self.img_size)
            .ok_or(ParseError::SizeOverflow)
    }

    /// Number of bytes the image digest covers: header, body and protected TLV area,
    /// `hdr_size + img_size + protect_tlv_size`, or [`ParseError::SizeOverflow`].
    pub fn hashed_len(&self) -> Result<u32, ParseError> {
        self.tlv_offset()?
            .checked_add(u32::from(self.protect_tlv_size))
            .ok_or(ParseError::SizeOverflow)
    }
}

/// A TLV info header (`struct image_tlv_info`): the area's magic and its total size,
/// info header included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlvInfo {
    /// `it_magic`: [`TLV_PROT_INFO_MAGIC`] or [`TLV_INFO_MAGIC`] in a valid image.
    pub magic: u16,
    /// `it_tlv_tot`: size of the area, these 4 bytes included.
    pub tlv_tot: u16,
}

impl TlvInfo {
    /// Read a TLV info header from the first [`TLV_INFO_SIZE`] bytes of `bytes`, or
    /// [`ParseError::Truncated`]. The magic is not checked.
    pub fn parse(bytes: &[u8]) -> Result<TlvInfo, ParseError> {
        let (&[m0, m1, t0, t1], _) = bytes
            .split_first_chunk::<TLV_INFO_SIZE>()
            .ok_or(ParseError::Truncated)?;
        Ok(TlvInfo {
            magic: u16::from_le_bytes([m0, m1]),
            tlv_tot: u16::from_le_bytes([t0, t1]),
        })
    }
}

/// What a TLV type means to keelsign. MCUboot types the parser does not name, and every
/// other type, are [`TlvKind::Unknown`]; they are yielded, never rejected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlvKind {
    /// [`IMAGE_TLV_KEYHASH`].
    KeyHash,
    /// [`IMAGE_TLV_PUBKEY`].
    PubKey,
    /// [`IMAGE_TLV_SHA256`].
    Sha256,
    /// [`IMAGE_TLV_SHA384`].
    Sha384,
    /// [`IMAGE_TLV_SHA512`].
    Sha512,
    /// [`IMAGE_TLV_RSA2048_PSS`].
    Rsa2048Pss,
    /// [`IMAGE_TLV_ECDSA_SIG`].
    EcdsaSig,
    /// [`IMAGE_TLV_RSA3072_PSS`].
    Rsa3072Pss,
    /// [`IMAGE_TLV_ED25519`].
    Ed25519,
    /// [`IMAGE_TLV_SIG_PURE`].
    SigPure,
    /// [`IMAGE_TLV_DEPENDENCY`].
    Dependency,
    /// [`IMAGE_TLV_SEC_CNT`].
    SecCnt,
    /// [`IMAGE_TLV_BOOT_RECORD`].
    BootRecord,
    /// [`TLV_KEELSIGN_KEY_ID`].
    KeelsignKeyId,
    /// [`TLV_MLDSA44_SIG`].
    MlDsa44Sig,
    /// [`TLV_MLDSA65_SIG`].
    MlDsa65Sig,
    /// [`TLV_LMS_HSS_SIG`].
    LmsHssSig,
    /// A type in the keelsign block reserved for future use (`0x4BA4..=0x4BAF`).
    KeelsignReserved(u16),
    /// Any other type.
    Unknown(u16),
}

impl TlvKind {
    /// The kind of TLV type `tlv_type`.
    pub fn of(tlv_type: u16) -> TlvKind {
        match tlv_type {
            IMAGE_TLV_KEYHASH => TlvKind::KeyHash,
            IMAGE_TLV_PUBKEY => TlvKind::PubKey,
            IMAGE_TLV_SHA256 => TlvKind::Sha256,
            IMAGE_TLV_SHA384 => TlvKind::Sha384,
            IMAGE_TLV_SHA512 => TlvKind::Sha512,
            IMAGE_TLV_RSA2048_PSS => TlvKind::Rsa2048Pss,
            IMAGE_TLV_ECDSA_SIG => TlvKind::EcdsaSig,
            IMAGE_TLV_RSA3072_PSS => TlvKind::Rsa3072Pss,
            IMAGE_TLV_ED25519 => TlvKind::Ed25519,
            IMAGE_TLV_SIG_PURE => TlvKind::SigPure,
            IMAGE_TLV_DEPENDENCY => TlvKind::Dependency,
            IMAGE_TLV_SEC_CNT => TlvKind::SecCnt,
            IMAGE_TLV_BOOT_RECORD => TlvKind::BootRecord,
            TLV_KEELSIGN_KEY_ID => TlvKind::KeelsignKeyId,
            TLV_MLDSA44_SIG => TlvKind::MlDsa44Sig,
            TLV_MLDSA65_SIG => TlvKind::MlDsa65Sig,
            TLV_LMS_HSS_SIG => TlvKind::LmsHssSig,
            t if KEELSIGN_TLV_RANGE.contains(&t) => TlvKind::KeelsignReserved(t),
            t => TlvKind::Unknown(t),
        }
    }
}

/// One TLV of a parsed image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// `it_type`.
    pub tlv_type: u16,
    /// The value: `it_len` bytes following the TLV header.
    pub value: &'a [u8],
    /// Whether the TLV is in the protected area.
    pub protected: bool,
}

impl<'a> Tlv<'a> {
    /// What the type means ([`TlvKind::of`]).
    pub fn kind(&self) -> TlvKind {
        TlvKind::of(self.tlv_type)
    }

    /// `(type, value)`, the item type [`select_pq_signature`](crate::select_pq_signature)
    /// takes.
    pub fn as_pair(&self) -> (u16, &'a [u8]) {
        (self.tlv_type, self.value)
    }
}

impl<'a> From<Tlv<'a>> for (u16, &'a [u8]) {
    fn from(tlv: Tlv<'a>) -> Self {
        tlv.as_pair()
    }
}

/// A validated TLV area (protected or unprotected).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlvArea<'a> {
    /// The TLVs, after the info header.
    tlvs: &'a [u8],
    /// Offset of the info header in the image, and of the area's end.
    start: u32,
    end: u32,
    protected: bool,
}

impl<'a> TlvArea<'a> {
    /// The area's byte range in the image, its info header included.
    pub fn range(&self) -> Range<u32> {
        self.start..self.end
    }

    /// Whether this is the protected area.
    pub fn is_protected(&self) -> bool {
        self.protected
    }

    /// The area's TLVs, in order. Never fails: the area was validated when the image was
    /// parsed.
    pub fn iter(&self) -> TlvIter<'a> {
        TlvIter {
            rest: self.tlvs,
            protected: self.protected,
        }
    }

    /// The area's TLVs as `(type, value)` pairs, the input of
    /// [`select_pq_signature`](crate::select_pq_signature) and
    /// [`verify_pq`](crate::verify_pq).
    ///
    /// PQ selection MUST use the unprotected area's pairs, `image.unprotected().pairs()`.
    /// keelsign TLVs are unprotected-only (docs/image-format.md), so keelsign TLVs in the
    /// protected area are ignored for PQ selection: a PQ signature there is inside `M` and
    /// can never be a valid signature over `M`. Rejecting such images is a candidate policy
    /// rule (SHA-46). See the [module docs](self#post-quantum-signature-selection).
    pub fn pairs(&self) -> impl Iterator<Item = (u16, &'a [u8])> + use<'a> {
        self.iter().map(|tlv| tlv.as_pair())
    }
}

/// Iterator over the TLVs of a [`TlvArea`].
#[derive(Clone, Debug)]
pub struct TlvIter<'a> {
    rest: &'a [u8],
    protected: bool,
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        // The area was validated by `walk_area`, so this cannot fail; if it somehow did,
        // the iteration ends rather than yield anything unchecked.
        match split_tlv(self.rest) {
            Ok((tlv_type, value, rest)) => {
                self.rest = rest;
                Some(Tlv {
                    tlv_type,
                    value,
                    protected: self.protected,
                })
            }
            Err(_) => {
                self.rest = &[];
                None
            }
        }
    }
}

/// A parsed, validated MCUboot image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image<'a> {
    /// The image header. Private so that a copied `Image` cannot have its header edited
    /// out of step with its TLV areas; read it with [`Image::header`].
    header: Header,
    protected: Option<TlvArea<'a>>,
    unprotected: TlvArea<'a>,
}

impl<'a> Image<'a> {
    /// Parse and validate a whole image: header, body and both TLV areas. Bytes after the
    /// unprotected TLV area (a slot trailer) are allowed; see [`Image::tlv_end`].
    ///
    /// # Error precedence
    ///
    /// When an input has several faults, the first check in this order decides the error:
    ///
    /// 1. Header errors, from [`Header::parse`]: [`ParseError::Truncated`] (fewer than
    ///    [`IMAGE_HEADER_SIZE`] bytes), then [`ParseError::BadMagic`], then
    ///    [`ParseError::HeaderTooSmall`].
    /// 2. [`ParseError::SizeOverflow`] for the whole hashed region
    ///    (`hdr_size + img_size + protect_tlv_size`) before any [`ParseError::Truncated`]
    ///    for the body or TLV areas.
    /// 3. For the protected area: its info magic ([`ParseError::BadTlvInfoMagic`]) and its
    ///    size against the header ([`ParseError::ProtectedSizeMismatch`]) before its walk;
    ///    with no protected area announced, a protected magic where the unprotected area
    ///    starts is [`ParseError::ProtectedSizeMismatch`]. Then the unprotected area's info
    ///    magic, then its walk.
    /// 4. Within an area: `tlv_tot < 4` ([`ParseError::LengthMismatch`]), then its end
    ///    ([`ParseError::SizeOverflow`], [`ParseError::Truncated`]), then its TLVs in
    ///    order. Within one TLV, [`ParseError::LengthMismatch`] (header or value past the
    ///    area) before [`ParseError::PqSignatureTooLong`].
    ///
    /// # Example
    ///
    /// ```
    /// use keelsign_verify::image::{Image, TlvKind};
    ///
    /// // A 32-byte header (hdr_size 32, img_size 4, version 1.2.3+4), a 4-byte body and
    /// // an unprotected TLV area holding one SEC_CNT TLV.
    /// const IMAGE: [u8; 48] = [
    ///     0x3D, 0xB8, 0xF3, 0x96, // ih_magic
    ///     0, 0, 0, 0, // ih_load_addr
    ///     32, 0, // ih_hdr_size
    ///     0, 0, // ih_protect_tlv_size
    ///     4, 0, 0, 0, // ih_img_size
    ///     0, 0, 0, 0, // ih_flags
    ///     1, 2, 3, 0, 4, 0, 0, 0, // ih_ver
    ///     0, 0, 0, 0, // _pad1
    ///     0xAA, 0xBB, 0xCC, 0xDD, // body
    ///     0x07, 0x69, 12, 0, // TLV info: magic 0x6907, tlv_tot 12
    ///     0x50, 0, 4, 0, 7, 0, 0, 0, // SEC_CNT = 7
    /// ];
    ///
    /// let image = Image::parse(&IMAGE)?;
    /// assert_eq!(image.header().img_size, 4);
    /// assert_eq!(image.header().version.build_num, 4);
    /// assert!(image.protected().is_none());
    /// assert_eq!(image.hashed_range(), 0..36);
    /// assert_eq!(image.tlv_end(), 48);
    /// let tlv = image.tlvs().next().unwrap();
    /// assert_eq!(tlv.kind(), TlvKind::SecCnt);
    /// assert_eq!(tlv.value, [7, 0, 0, 0]);
    /// # Ok::<(), keelsign_verify::image::ParseError>(())
    /// ```
    pub fn parse(bytes: &'a [u8]) -> Result<Image<'a>, ParseError> {
        let header = Header::parse(bytes)?;
        // Size overflow is reported before truncation, for the whole hashed region.
        header.hashed_len()?;
        let tlv_offset = to_usize(header.tlv_offset()?)?;
        let tlv_bytes = bytes.get(tlv_offset..).ok_or(ParseError::Truncated)?;
        Image::parse_parts(header, tlv_bytes)
    }

    /// Validate the TLV areas of an image whose header was parsed separately (for
    /// example, read from flash in pieces). `tlv_bytes` starts at
    /// [`Header::tlv_offset`]; offsets in the result are still relative to the image
    /// start.
    ///
    /// `header` is re-checked: a `hdr_size` below [`IMAGE_HEADER_SIZE`] is
    /// [`ParseError::HeaderTooSmall`], however the [`Header`] was made (its fields are
    /// public, so it can be built by hand). The magic is not re-checked: a [`Header`] does
    /// not hold it.
    ///
    /// # Contract
    ///
    /// The caller must ensure that:
    ///
    /// - `tlv_bytes` is exactly the bytes from [`Header::tlv_offset`] to the end of the
    ///   slot's usable area, no fewer (so [`ParseError::Truncated`] means the image does not
    ///   fit the slot) and no more (so TLVs past the slot are rejected, as MCUboot rejects an
    ///   image whose `tlv_end` exceeds the slot, `image_validate.c:300`).
    /// - The bytes hashed over [`Image::hashed_range`] are the same bytes `header` was
    ///   parsed from: the header must not be re-read from storage that could have changed
    ///   between parsing and hashing.
    pub fn parse_parts(header: Header, tlv_bytes: &'a [u8]) -> Result<Image<'a>, ParseError> {
        if usize::from(header.hdr_size) < IMAGE_HEADER_SIZE {
            return Err(ParseError::HeaderTooSmall);
        }
        let tlv_offset = header.tlv_offset()?;
        let hashed_len = header.hashed_len()?;
        let prot_size = header.protect_tlv_size;

        let protected = if prot_size != 0 {
            let info = TlvInfo::parse(tlv_bytes)?;
            if info.magic != TLV_PROT_INFO_MAGIC {
                return Err(ParseError::BadTlvInfoMagic);
            }
            if info.tlv_tot != prot_size {
                return Err(ParseError::ProtectedSizeMismatch);
            }
            Some(area(tlv_bytes, tlv_offset, info.tlv_tot, true)?)
        } else {
            let (&[m0, m1], _) = tlv_bytes
                .split_first_chunk::<2>()
                .ok_or(ParseError::Truncated)?;
            if u16::from_le_bytes([m0, m1]) == TLV_PROT_INFO_MAGIC {
                return Err(ParseError::ProtectedSizeMismatch);
            }
            None
        };

        let unprotected_bytes = tlv_bytes
            .get(usize::from(prot_size)..)
            .ok_or(ParseError::Truncated)?;
        let info = TlvInfo::parse(unprotected_bytes)?;
        if info.magic != TLV_INFO_MAGIC {
            return Err(ParseError::BadTlvInfoMagic);
        }
        let unprotected = area(unprotected_bytes, hashed_len, info.tlv_tot, false)?;
        Ok(Image {
            header,
            protected,
            unprotected,
        })
    }

    /// The image header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The protected TLV area, if the header announces one.
    pub fn protected(&self) -> Option<&TlvArea<'a>> {
        self.protected.as_ref()
    }

    /// The unprotected TLV area.
    pub fn unprotected(&self) -> &TlvArea<'a> {
        &self.unprotected
    }

    /// The bytes the image digest `M` covers: header, body and protected TLV area
    /// (`0..hdr_size + img_size + protect_tlv_size`).
    pub fn hashed_range(&self) -> Range<u32> {
        // The unprotected area starts where the hashed bytes end.
        0..self.unprotected.start
    }

    /// Where the image ends: the end of the unprotected TLV area. Anything after it is
    /// not part of the image.
    pub fn tlv_end(&self) -> u32 {
        self.unprotected.end
    }

    /// Every TLV: the protected area's, then the unprotected area's.
    ///
    /// Not the input of PQ selection: that MUST be `self.unprotected().pairs()`. keelsign
    /// TLVs are unprotected-only (docs/image-format.md), so keelsign TLVs in the protected
    /// area, which this iterator yields, are ignored for PQ selection; a PQ signature there
    /// is inside `M` and can never be a valid signature over `M`. Rejecting such images is
    /// a candidate policy rule (SHA-46).
    pub fn tlvs(&self) -> impl Iterator<Item = Tlv<'a>> + use<'a> {
        self.protected
            .map(|area| area.iter())
            .into_iter()
            .flatten()
            .chain(self.unprotected.iter())
    }
}

/// Convert an image offset to `usize` ([`ParseError::SizeOverflow`] if it does not fit).
fn to_usize(offset: u32) -> Result<usize, ParseError> {
    usize::try_from(offset).map_err(|_| ParseError::SizeOverflow)
}

/// Validate the TLV area of `tlv_tot` bytes at the start of `bytes`, which is at image
/// offset `start`.
fn area(
    bytes: &[u8],
    start: u32,
    tlv_tot: u16,
    protected: bool,
) -> Result<TlvArea<'_>, ParseError> {
    if usize::from(tlv_tot) < TLV_INFO_SIZE {
        return Err(ParseError::LengthMismatch);
    }
    let end = start
        .checked_add(u32::from(tlv_tot))
        .ok_or(ParseError::SizeOverflow)?;
    let tlvs = bytes
        .get(TLV_INFO_SIZE..usize::from(tlv_tot))
        .ok_or(ParseError::Truncated)?;
    let mut rest = tlvs;
    while !rest.is_empty() {
        let (_, _, next) = split_tlv(rest)?;
        rest = next;
    }
    Ok(TlvArea {
        tlvs,
        start,
        end,
        protected,
    })
}

/// Split the first TLV off `rest`: `(type, value, the bytes after it)`.
fn split_tlv(rest: &[u8]) -> Result<(u16, &[u8], &[u8]), ParseError> {
    let (&[t0, t1, l0, l1], tail) = rest
        .split_first_chunk::<TLV_HEADER_SIZE>()
        .ok_or(ParseError::LengthMismatch)?;
    let tlv_type = u16::from_le_bytes([t0, t1]);
    let len = usize::from(u16::from_le_bytes([l0, l1]));
    let (value, next) = tail
        .split_at_checked(len)
        .ok_or(ParseError::LengthMismatch)?;
    if is_pq_signature(tlv_type) && len > MAX_PQ_SIGNATURE_LEN {
        return Err(ParseError::PqSignatureTooLong);
    }
    Ok((tlv_type, value, next))
}

/// Whether `tlv_type` is a post-quantum signature TLV, bounded by [`MAX_PQ_SIGNATURE_LEN`].
/// Derived from [`Algorithm`] so that a future PQ TLV cannot escape the bound.
fn is_pq_signature(tlv_type: u16) -> bool {
    Algorithm::from_tlv_type(tlv_type).is_some()
}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::collections::BTreeSet;
    use std::format;
    use std::string::{String, ToString};
    use std::vec;
    use std::vec::Vec;

    use proptest::collection::vec as pvec;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::algorithm::Algorithm;
    use crate::error::Error;
    use crate::select_pq_signature;

    // ---- Fixtures and MANIFEST.json ---------------------------------------------------

    const MANIFEST: &str = include_str!("../../tests/fixtures/images/MANIFEST.json");

    /// The SHA-37 sample images (keelsign TLVs appended to imgtool output).
    const SAMPLES: [(&str, &[u8]); 7] = [
        (
            "keelsign-lms-m32-h5.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-lms-m32-h5.bin"),
        ),
        (
            "keelsign-hss2-m32-h5h5.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-hss2-m32-h5h5.bin"),
        ),
        (
            "keelsign-lms-protected-tlvs.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-lms-protected-tlvs.bin"),
        ),
        (
            "keelsign-hybrid-ed25519-lms.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin"),
        ),
        (
            "keelsign-mldsa44.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-mldsa44.bin"),
        ),
        (
            "keelsign-mldsa65.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-mldsa65.bin"),
        ),
        (
            "keelsign-dual-pq-invalid.bin",
            include_bytes!("../../tests/fixtures/images/keelsign-dual-pq-invalid.bin"),
        ),
    ];

    /// The SHA-35 golden MCUboot images (little-endian, parse Ok).
    const GOLDEN: [(&str, &[u8]); 4] = [
        (
            "mcuboot-rsa2048.bin",
            include_bytes!("../../tests/fixtures/images/mcuboot-rsa2048.bin"),
        ),
        (
            "mcuboot-ecdsa-p256.bin",
            include_bytes!("../../tests/fixtures/images/mcuboot-ecdsa-p256.bin"),
        ),
        (
            "mcuboot-ed25519.bin",
            include_bytes!("../../tests/fixtures/images/mcuboot-ed25519.bin"),
        ),
        (
            "mcuboot-ed25519-padded.bin",
            include_bytes!("../../tests/fixtures/images/mcuboot-ed25519-padded.bin"),
        ),
    ];

    const BIG_ENDIAN: &[u8] =
        include_bytes!("../../tests/fixtures/images/rejected/mcuboot-ed25519-bigendian.bin");
    const ED25519_SPKI: &[u8] =
        include_bytes!("../../tests/fixtures/images/keys/ed25519-test-key.spki.der");

    fn all_valid() -> impl Iterator<Item = (&'static str, &'static [u8])> {
        SAMPLES.into_iter().chain(GOLDEN)
    }

    fn fixture(name: &str) -> &'static [u8] {
        all_valid()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no fixture {name}"))
            .1
    }

    /// The JSON object under `"key": {` (brace-matched; the manifest has no braces in
    /// strings).
    fn object<'j>(json: &'j str, key: &str) -> &'j str {
        let start = json
            .find(&format!("\"{key}\": {{"))
            .unwrap_or_else(|| panic!("MANIFEST.json has no object `{key}`"));
        let body = &json[start..];
        let open = body.find('{').unwrap();
        let mut depth = 0usize;
        for (i, c) in body[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &body[open..=open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unterminated object `{key}`");
    }

    fn entry(name: &str) -> &'static str {
        object(object(MANIFEST, "outputs"), name)
    }

    /// A scalar field of a JSON object, without quotes.
    fn field(object: &str, name: &str) -> String {
        let needle = format!("\"{name}\": ");
        let start = object
            .find(&needle)
            .unwrap_or_else(|| panic!("no field `{name}`"))
            + needle.len();
        let rest = &object[start..];
        let end = rest.find([',', '\n']).unwrap_or(rest.len());
        rest[..end].trim().trim_matches('"').to_string()
    }

    fn num(object: &str, name: &str) -> u64 {
        field(object, name).parse().unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn types(text: &str) -> Vec<u16> {
        text.split_whitespace()
            .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
            .collect()
    }

    fn lens(text: &str) -> Vec<usize> {
        text.split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn range(r: Range<u32>) -> Range<usize> {
        r.start as usize..r.end as usize
    }

    fn values(area: &TlvArea<'_>, tlv_type: u16) -> Vec<Vec<u8>> {
        area.pairs()
            .filter(|(t, _)| *t == tlv_type)
            .map(|(_, v)| v.to_vec())
            .collect()
    }

    /// Header fields, TLV types and lengths per area, and the tlv_end recorded in the
    /// manifest for `name`.
    fn assert_matches_manifest(name: &str, image: &Image<'_>) {
        let entry = entry(name);
        let header = object(entry, "header");
        assert_eq!(
            u64::from(image.header().hdr_size),
            num(header, "hdr_size"),
            "{name}"
        );
        assert_eq!(
            u64::from(image.header().protect_tlv_size),
            num(header, "protect_tlv_size"),
            "{name}"
        );
        assert_eq!(
            u64::from(image.header().img_size),
            num(header, "img_size"),
            "{name}"
        );
        assert_eq!(
            u64::from(image.header().flags.0),
            num(header, "flags"),
            "{name}"
        );
        let v = image.header().version;
        assert_eq!(
            format!("{}.{}.{}+{}", v.major, v.minor, v.revision, v.build_num),
            field(header, "version"),
            "{name}"
        );
        let prot: Vec<Tlv<'_>> = image
            .protected()
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        let unprot: Vec<Tlv<'_>> = image.unprotected().iter().collect();
        assert_eq!(
            prot.iter().map(|t| t.tlv_type).collect::<Vec<_>>(),
            types(&field(entry, "protected_tlvs")),
            "{name}"
        );
        assert_eq!(
            prot.iter().map(|t| t.value.len()).collect::<Vec<_>>(),
            lens(&field(entry, "protected_tlv_lens")),
            "{name}"
        );
        assert_eq!(
            unprot.iter().map(|t| t.tlv_type).collect::<Vec<_>>(),
            types(&field(entry, "unprotected_tlvs")),
            "{name}"
        );
        assert_eq!(
            unprot.iter().map(|t| t.value.len()).collect::<Vec<_>>(),
            lens(&field(entry, "unprotected_tlv_lens")),
            "{name}"
        );
        assert!(prot.iter().all(|t| t.protected) && unprot.iter().all(|t| !t.protected));
        assert_eq!(u64::from(image.tlv_end()), num(entry, "tlv_end"), "{name}");
        assert_eq!(field(entry, "expect_parse"), "Ok", "{name}");
    }

    // ---- Synthetic images -------------------------------------------------------------

    fn header_bytes(hdr_size: u16, protect_tlv_size: u16, img_size: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&IMAGE_MAGIC.to_le_bytes());
        h.extend_from_slice(&0x1000u32.to_le_bytes());
        h.extend_from_slice(&hdr_size.to_le_bytes());
        h.extend_from_slice(&protect_tlv_size.to_le_bytes());
        h.extend_from_slice(&img_size.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&[1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(h.len(), IMAGE_HEADER_SIZE);
        h
    }

    fn area_bytes(magic: u16, tlvs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in tlvs {
            body.extend_from_slice(&t.to_le_bytes());
            body.extend_from_slice(&u16::try_from(v.len()).unwrap().to_le_bytes());
            body.extend_from_slice(v);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_le_bytes());
        out.extend(body);
        out
    }

    /// A 32-byte header, a 4-byte body and the given TLV areas.
    fn synth(protected: Option<&[(u16, &[u8])]>, unprotected: &[(u16, &[u8])]) -> Vec<u8> {
        let prot = protected.map(|t| area_bytes(TLV_PROT_INFO_MAGIC, t));
        let prot_len = prot.as_ref().map_or(0, Vec::len);
        let mut d = header_bytes(32, u16::try_from(prot_len).unwrap(), 4);
        d.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        d.extend(prot.unwrap_or_default());
        d.extend(area_bytes(TLV_INFO_MAGIC, unprotected));
        d
    }

    fn set_u16(d: &mut [u8], at: usize, v: u16) {
        d[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn set_u32(d: &mut [u8], at: usize, v: u32) {
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    // ---- Reference parser (oracle) ----------------------------------------------------

    /// (protected, type, value offset, value length) of every TLV.
    type Walk = Vec<(bool, u16, usize, usize)>;

    /// An independent, deliberately plain restatement of the parsing rules (module docs),
    /// in u64 arithmetic with explicit checks, to predict the parser's result.
    fn oracle(d: &[u8]) -> Result<(u64, u64, Walk), ParseError> {
        use ParseError::*;
        let len = d.len() as u64;
        let u16_at = |at: u64| u16::from_le_bytes([d[at as usize], d[at as usize + 1]]);
        if len < 32 {
            return Err(Truncated);
        }
        if u32::from_le_bytes(d[0..4].try_into().unwrap()) != IMAGE_MAGIC {
            return Err(BadMagic);
        }
        let hdr = u64::from(u16_at(8));
        let prot = u64::from(u16_at(10));
        let img = u64::from(u32::from_le_bytes(d[12..16].try_into().unwrap()));
        if hdr < 32 {
            return Err(HeaderTooSmall);
        }
        let tlv_off = hdr + img;
        let hashed = tlv_off + prot;
        if tlv_off > u64::from(u32::MAX) || hashed > u64::from(u32::MAX) {
            return Err(SizeOverflow);
        }
        if tlv_off > len {
            return Err(Truncated);
        }
        let mut walk = Vec::new();
        let area = |off: u64, tot: u64, protected: bool, walk: &mut Walk| {
            if tot < 4 {
                return Err(LengthMismatch);
            }
            let end = off + tot;
            if end > u64::from(u32::MAX) {
                return Err(SizeOverflow);
            }
            if end > len {
                return Err(Truncated);
            }
            let mut pos = off + 4;
            while pos < end {
                if end - pos < 4 {
                    return Err(LengthMismatch);
                }
                let t = u16_at(pos);
                let l = u64::from(u16_at(pos + 2));
                if pos + 4 + l > end {
                    return Err(LengthMismatch);
                }
                if (0x4BA1..=0x4BA3).contains(&t) && l > MAX_PQ_SIGNATURE_LEN as u64 {
                    return Err(PqSignatureTooLong);
                }
                walk.push((protected, t, (pos + 4) as usize, l as usize));
                pos += 4 + l;
            }
            Ok(end)
        };
        if prot != 0 {
            if tlv_off + 4 > len {
                return Err(Truncated);
            }
            if u16_at(tlv_off) != TLV_PROT_INFO_MAGIC {
                return Err(BadTlvInfoMagic);
            }
            let tot = u64::from(u16_at(tlv_off + 2));
            if tot != prot {
                return Err(ProtectedSizeMismatch);
            }
            area(tlv_off, tot, true, &mut walk)?;
        } else {
            if tlv_off + 2 > len {
                return Err(Truncated);
            }
            if u16_at(tlv_off) == TLV_PROT_INFO_MAGIC {
                return Err(ProtectedSizeMismatch);
            }
        }
        if hashed + 4 > len {
            return Err(Truncated);
        }
        if u16_at(hashed) != TLV_INFO_MAGIC {
            return Err(BadTlvInfoMagic);
        }
        let end = area(hashed, u64::from(u16_at(hashed + 2)), false, &mut walk)?;
        Ok((hashed, end, walk))
    }

    /// The parser's result in the oracle's terms.
    fn summary(d: &[u8]) -> Result<(u64, u64, Walk), ParseError> {
        let image = Image::parse(d)?;
        let base = d.as_ptr() as usize;
        let walk = image
            .tlvs()
            .map(|t| {
                (
                    t.protected,
                    t.tlv_type,
                    t.value.as_ptr() as usize - base,
                    t.value.len(),
                )
            })
            .collect();
        Ok((
            u64::from(image.hashed_range().end),
            u64::from(image.tlv_end()),
            walk,
        ))
    }

    /// Every TLV value lies inside its area, both areas inside the input, and
    /// `hashed_range().end <= tlv_end() <= len`.
    fn assert_in_bounds(d: &[u8], image: &Image<'_>) {
        let base = d.as_ptr() as usize;
        let hashed = image.hashed_range();
        assert_eq!(hashed.start, 0);
        assert!(hashed.end <= image.tlv_end());
        assert!(image.tlv_end() as usize <= d.len());
        assert_eq!(image.unprotected().range().start, hashed.end);
        assert_eq!(image.unprotected().range().end, image.tlv_end());
        let areas = image.protected().into_iter().chain([image.unprotected()]);
        for area in areas {
            let r = range(area.range());
            assert!(r.end <= d.len());
            let mut covered = TLV_INFO_SIZE;
            for tlv in area.iter() {
                let off = tlv.value.as_ptr() as usize - base;
                assert!(off >= r.start + TLV_INFO_SIZE + TLV_HEADER_SIZE);
                assert!(off + tlv.value.len() <= r.end);
                assert_eq!(tlv.protected, area.is_protected());
                covered += TLV_HEADER_SIZE + tlv.value.len();
            }
            assert_eq!(covered, r.len(), "the TLVs exactly fill their area");
        }
        if let Some(p) = image.protected() {
            assert_eq!(p.range().end, hashed.end);
            assert_eq!(Ok(p.range().start), image.header().tlv_offset());
        }
    }

    // ---- Tests ------------------------------------------------------------------------

    /// SHA-37 TP1 (the half deferred to the parser): every sample image parses, matches
    /// its manifest, its SHA256 TLV is the digest of `hashed_range()`, and its
    /// unprotected pairs select the PQ signature the manifest expects.
    #[test]
    fn keelsign_sample_images_parse() {
        for (name, data) in SAMPLES {
            let image = Image::parse(data).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_matches_manifest(name, &image);
            assert_eq!(image.header().hdr_size, 0x200, "{name}");
            assert_eq!(image.header().img_size, 1536, "{name}");
            assert_eq!(image.tlv_end() as usize, data.len(), "{name}");
            assert_in_bounds(data, &image);
            let entry = entry(name);

            let digest = sha256(&data[range(image.hashed_range())]);
            assert_eq!(
                values(image.unprotected(), IMAGE_TLV_SHA256),
                [digest.to_vec()],
                "{name}"
            );
            assert_eq!(digest.to_vec(), hex(&field(entry, "digest_hex")), "{name}");

            let selected = select_pq_signature(image.unprotected().pairs());
            match field(entry, "expect_verify_pq").as_str() {
                "MultiplePqSignatures" => {
                    assert_eq!(selected, Err(Error::MultiplePqSignatures), "{name}")
                }
                _ => {
                    let selected = selected.unwrap();
                    let alg = match field(entry, "algorithm").as_str() {
                        "LmsHss" => Algorithm::LmsHss,
                        "MlDsa44" => Algorithm::MlDsa44,
                        "MlDsa65" => Algorithm::MlDsa65,
                        other => panic!("{other}"),
                    };
                    assert_eq!(selected.algorithm, alg, "{name}");
                    assert_eq!(selected.key_id, hex(&field(entry, "key_id_hex")), "{name}");
                    assert_eq!(
                        selected.signature.len().to_string(),
                        field(entry, "signature_lens"),
                        "{name}"
                    );
                }
            }
        }
    }

    /// The protected SEC_CNT / BOOT_RECORD / DEPENDENCY and unprotected SHA256 / KEYHASH /
    /// signature TLVs of a golden image, with their kinds and values.
    fn golden_exposes_every_tlv(name: &str, sig: TlvKind, sig_lens: Range<usize>) {
        let data = fixture(name);
        let image = Image::parse(data).unwrap();
        assert_matches_manifest(name, &image);
        assert_in_bounds(data, &image);
        assert_eq!(image.header().flags, ImageFlags(0));
        assert_eq!(
            image.header().version,
            ImageVersion {
                major: 1,
                minor: 2,
                revision: 3,
                build_num: 4
            }
        );
        let entry = entry(name);

        let prot: Vec<Tlv<'_>> = image.protected().unwrap().iter().collect();
        assert_eq!(
            prot.iter().map(Tlv::kind).collect::<Vec<_>>(),
            [TlvKind::SecCnt, TlvKind::BootRecord, TlvKind::Dependency],
            "{name}"
        );
        // SEC_CNT: the security counter 7, little-endian u32.
        assert_eq!(prot[0].value, 7u32.to_le_bytes(), "{name}");
        // DEPENDENCY: image 1 (u8, 3 pad bytes), version 1.2.3+4.
        assert_eq!(
            prot[2].value,
            [1, 0, 0, 0, 1, 2, 3, 0, 4, 0, 0, 0],
            "{name}"
        );

        let unprot: Vec<Tlv<'_>> = image.unprotected().iter().collect();
        assert_eq!(
            unprot.iter().map(Tlv::kind).collect::<Vec<_>>(),
            [TlvKind::Sha256, TlvKind::KeyHash, sig],
            "{name}"
        );
        // SHA256 is M, recomputed over hashed_range() (header, body, protected TLVs).
        let digest = sha256(&data[range(image.hashed_range())]);
        assert_eq!(unprot[0].value, digest, "{name}");
        assert_eq!(digest.to_vec(), hex(&field(entry, "digest_hex")), "{name}");
        // KEYHASH is SHA-256 of the key's public bytes as imgtool embeds them.
        let key = field(entry, "key");
        let public = if key == "keys/ed25519-test-key.pem" {
            ED25519_SPKI.to_vec()
        } else {
            hex(&field(
                object(object(MANIFEST, "keys"), &key),
                "public_der_hex",
            ))
        };
        assert_eq!(unprot[1].value, sha256(&public), "{name}");
        assert_eq!(unprot[1].value, hex(&field(entry, "keyhash_hex")), "{name}");
        // BOOT_RECORD (CBOR) names the signer by the same key hash.
        assert!(
            prot[1].value.windows(32).any(|w| w == unprot[1].value),
            "{name}: boot record signer ID"
        );
        assert!(
            sig_lens.contains(&unprot[2].value.len()),
            "{name}: signature length {}",
            unprot[2].value.len()
        );
        // No keelsign TLVs: nothing to select.
        assert_eq!(
            select_pq_signature(image.unprotected().pairs()),
            Err(Error::MissingPqSignature)
        );
    }

    #[test]
    fn golden_rsa2048_exposes_every_tlv() {
        golden_exposes_every_tlv("mcuboot-rsa2048.bin", TlvKind::Rsa2048Pss, 256..257);
    }

    #[test]
    fn golden_ecdsa_p256_exposes_every_tlv() {
        // DER-encoded (r, s): 70 to 72 bytes.
        golden_exposes_every_tlv("mcuboot-ecdsa-p256.bin", TlvKind::EcdsaSig, 70..73);
    }

    #[test]
    fn golden_ed25519_exposes_every_tlv() {
        golden_exposes_every_tlv("mcuboot-ed25519.bin", TlvKind::Ed25519, 64..65);
    }

    #[test]
    fn padded_image_allows_trailing_bytes() {
        let padded = fixture("mcuboot-ed25519-padded.bin");
        let plain = fixture("mcuboot-ed25519.bin");
        let image = Image::parse(padded).unwrap();
        assert_matches_manifest("mcuboot-ed25519-padded.bin", &image);
        assert_eq!(padded.len(), 0x2000);
        assert_eq!(image.tlv_end() as usize, plain.len());
        assert!((image.tlv_end() as usize) < padded.len());
        // The image part is the unpadded image; the TLVs are the same.
        assert_eq!(&padded[..plain.len()], plain);
        let plain_image = Image::parse(plain).unwrap();
        assert!(image.tlvs().eq(plain_image.tlvs()));
        // The trailer ends with MCUboot's boot magic and is never read as TLVs.
        let boot_magic = [
            0x77, 0xc2, 0x95, 0xf3, 0x60, 0xd2, 0xef, 0x7f, 0x35, 0x52, 0x50, 0x0f, 0x2c, 0xb6,
            0x79, 0x80,
        ];
        assert_eq!(padded[padded.len() - 16..], boot_magic);
        // Any trailing bytes are allowed.
        for tail in [&[0u8][..], &[0xFF; 100], &boot_magic] {
            let mut d = plain.to_vec();
            d.extend_from_slice(tail);
            let image = Image::parse(&d).unwrap();
            assert_eq!(image.tlv_end() as usize, plain.len());
            assert!(image.tlvs().eq(plain_image.tlvs()));
        }
    }

    #[test]
    fn big_endian_image_is_bad_magic() {
        assert_eq!(
            field(
                entry("rejected/mcuboot-ed25519-bigendian.bin"),
                "expect_parse"
            ),
            "BadMagic"
        );
        assert_eq!(BIG_ENDIAN[..4], IMAGE_MAGIC.to_be_bytes());
        assert_eq!(Image::parse(BIG_ENDIAN), Err(ParseError::BadMagic));
        assert_eq!(Header::parse(BIG_ENDIAN), Err(ParseError::BadMagic));
        // Byte-swapping the magic of any valid image gives the same.
        for (name, data) in all_valid() {
            let mut d = data.to_vec();
            d[..4].reverse();
            assert_eq!(Image::parse(&d), Err(ParseError::BadMagic), "{name}");
        }
    }

    #[test]
    fn big_endian_tlv_info_is_bad_tlv_info_magic() {
        for (name, data) in all_valid() {
            let image = Image::parse(data).unwrap();
            let tlv_off = image.header().tlv_offset().unwrap() as usize;
            let hashed = image.hashed_range().end as usize;
            // The protected info header written big-endian.
            if image.protected().is_some() {
                let mut d = data.to_vec();
                d[tlv_off..tlv_off + 2].reverse();
                d[tlv_off + 2..tlv_off + 4].reverse();
                assert_eq!(Image::parse(&d), Err(ParseError::BadTlvInfoMagic), "{name}");
            }
            // The unprotected info header written big-endian.
            let mut d = data.to_vec();
            d[hashed..hashed + 2].reverse();
            d[hashed + 2..hashed + 4].reverse();
            assert_eq!(Image::parse(&d), Err(ParseError::BadTlvInfoMagic), "{name}");
        }
    }

    #[test]
    fn truncation_at_every_boundary_is_truncated() {
        for (name, data) in all_valid() {
            let image = Image::parse(data).unwrap();
            let end = image.tlv_end() as usize;
            let tlv_off = image.header().tlv_offset().unwrap() as usize;
            let hashed = image.hashed_range().end as usize;
            // Every structural boundary, and one byte either side.
            let mut boundaries = vec![
                0,
                4,
                IMAGE_HEADER_SIZE,
                usize::from(image.header().hdr_size),
            ];
            boundaries.extend([tlv_off, tlv_off + 2, tlv_off + TLV_INFO_SIZE, hashed]);
            boundaries.extend([hashed + 2, hashed + TLV_INFO_SIZE]);
            let base = data.as_ptr() as usize;
            for tlv in image.tlvs() {
                let value = tlv.value.as_ptr() as usize - base;
                let header = value - TLV_HEADER_SIZE;
                boundaries.extend([header, header + 2, value, value + tlv.value.len()]);
            }
            for b in boundaries {
                for n in [b.saturating_sub(1), b, b + 1] {
                    if n < end {
                        assert_eq!(
                            Image::parse(&data[..n]),
                            Err(ParseError::Truncated),
                            "{name}: {n} of {end} bytes"
                        );
                    }
                }
            }
            // Every prefix: no panic, and Truncated until the image is complete.
            for n in 0..=data.len() {
                let result = Image::parse(&data[..n]);
                if n < end {
                    assert_eq!(result, Err(ParseError::Truncated), "{name}: {n} bytes");
                } else {
                    assert_eq!(result.unwrap().tlv_end() as usize, end, "{name}: {n} bytes");
                }
            }
        }
        // The rejected image is BadMagic from 32 bytes on.
        for n in 0..BIG_ENDIAN.len() {
            let expected = if n < 32 {
                ParseError::Truncated
            } else {
                ParseError::BadMagic
            };
            assert_eq!(Image::parse(&BIG_ENDIAN[..n]), Err(expected));
        }
    }

    #[test]
    fn bit_flips_in_magic_and_length_fields_give_expected_variants() {
        let mut seen = BTreeSet::new();
        let mut flips = 0;
        for (name, data) in all_valid() {
            let image = Image::parse(data).unwrap();
            let tlv_off = image.header().tlv_offset().unwrap() as usize;
            let hashed = image.hashed_range().end as usize;
            // (offset, bytes) of every magic and length field.
            let mut fields = vec![(0, 4), (8, 2), (10, 2), (12, 4)];
            if image.protected().is_some() {
                fields.extend([(tlv_off, 2), (tlv_off + 2, 2)]);
            }
            fields.extend([(hashed, 2), (hashed + 2, 2)]);
            let base = data.as_ptr() as usize;
            for tlv in image.tlvs() {
                fields.push((tlv.value.as_ptr() as usize - base - 2, 2));
            }
            for (at, width) in fields {
                for bit in 0..width * 8 {
                    let mut d = data.to_vec();
                    d[at + bit / 8] ^= 1 << (bit % 8);
                    let expected = oracle(&d);
                    assert_eq!(summary(&d), expected, "{name}: byte {at:#x} bit {bit}");
                    if let Err(e) = expected {
                        seen.insert(format!("{e:?}"));
                    }
                    // Fields whose every flip has a fixed answer.
                    if at == 0 {
                        assert_eq!(expected, Err(ParseError::BadMagic), "{name}");
                    }
                    if image.protected().is_some() && at == tlv_off {
                        assert_eq!(expected, Err(ParseError::BadTlvInfoMagic), "{name}");
                    }
                    if image.protected().is_some() && at == tlv_off + 2 {
                        assert_eq!(expected, Err(ParseError::ProtectedSizeMismatch), "{name}");
                    }
                    if at == hashed {
                        assert!(
                            matches!(
                                expected,
                                Err(ParseError::BadTlvInfoMagic)
                                    | Err(ParseError::ProtectedSizeMismatch)
                            ),
                            "{name}"
                        );
                    }
                    flips += 1;
                }
            }
        }
        assert!(flips > 1000, "{flips}");
        // Each field class produced the variant it guards. (PqSignatureTooLong cannot come
        // from one flip here: a longer PQ length first overruns its area, which is
        // LengthMismatch; pq_signature_tlv_longer_than_max_is_rejected covers it.)
        for variant in [
            "BadMagic",
            "Truncated",
            "HeaderTooSmall",
            "BadTlvInfoMagic",
            "ProtectedSizeMismatch",
            "LengthMismatch",
        ] {
            assert!(
                seen.contains(variant),
                "no bit flip gave {variant}: {seen:?}"
            );
        }
    }

    #[test]
    fn pq_signature_tlv_longer_than_max_is_rejected() {
        let max = vec![0x5A; MAX_PQ_SIGNATURE_LEN];
        let over = vec![0x5A; MAX_PQ_SIGNATURE_LEN + 1];
        for t in [TLV_MLDSA44_SIG, TLV_MLDSA65_SIG, TLV_LMS_HSS_SIG] {
            let ok = synth(None, &[(t, &max)]);
            let image = Image::parse(&ok).unwrap();
            assert_eq!(
                image.tlvs().next().unwrap().value.len(),
                MAX_PQ_SIGNATURE_LEN
            );
            for d in [
                synth(None, &[(IMAGE_TLV_SHA256, &[0; 32]), (t, &over)]),
                synth(Some(&[(t, &over)]), &[]),
            ] {
                assert_eq!(
                    Image::parse(&d),
                    Err(ParseError::PqSignatureTooLong),
                    "{t:#06x}"
                );
            }
        }
        // The key-ID TLV, the reserved block and other types have no such bound.
        for t in [TLV_KEELSIGN_KEY_ID, 0x4BA4, 0x4BA0 - 1, IMAGE_TLV_ED25519] {
            let d = synth(Some(&[(t, &over)]), &[(t, &over)]);
            assert!(Image::parse(&d).is_ok(), "{t:#06x}");
        }
    }

    #[test]
    fn protected_size_zero_with_prot_magic_is_mismatch() {
        // A well-formed protected area that the header does not announce.
        let mut d = synth(Some(&[(IMAGE_TLV_SEC_CNT, &[7, 0, 0, 0])]), &[]);
        set_u16(&mut d, 10, 0);
        assert_eq!(Image::parse(&d), Err(ParseError::ProtectedSizeMismatch));
        // A lone protected magic where the unprotected area should start.
        let mut d = synth(None, &[]);
        set_u16(&mut d, 36, TLV_PROT_INFO_MAGIC);
        assert_eq!(Image::parse(&d), Err(ParseError::ProtectedSizeMismatch));
    }

    #[test]
    fn protected_size_nonzero_needs_prot_magic() {
        let prot: &[(u16, &[u8])] = &[(IMAGE_TLV_SEC_CNT, &[7, 0, 0, 0])];
        let good = synth(Some(prot), &[]);
        let image = Image::parse(&good).unwrap();
        assert_eq!(image.protected().unwrap().range(), 36..48);
        // The protected area with the unprotected magic, or any other.
        for magic in [TLV_INFO_MAGIC, 0x0000, 0xFFFF, 0x0869] {
            let mut d = good.clone();
            set_u16(&mut d, 36, magic);
            assert_eq!(
                Image::parse(&d),
                Err(ParseError::BadTlvInfoMagic),
                "{magic:#06x}"
            );
        }
        // The header announces a protected area, but the unprotected one follows the body.
        let mut d = synth(None, &[]);
        set_u16(&mut d, 10, 4);
        assert_eq!(Image::parse(&d), Err(ParseError::BadTlvInfoMagic));
        // tlv_tot must equal protect_tlv_size, both ways.
        for size in [11, 13, 4, 0x7FFF] {
            let mut d = good.clone();
            set_u16(&mut d, 10, size);
            assert_eq!(
                Image::parse(&d),
                Err(ParseError::ProtectedSizeMismatch),
                "{size}"
            );
            let mut d = good.clone();
            set_u16(&mut d, 38, size);
            assert_eq!(
                Image::parse(&d),
                Err(ParseError::ProtectedSizeMismatch),
                "{size}"
            );
        }
    }

    #[test]
    fn tlv_tot_below_four_is_length_mismatch() {
        for tot in 0..4u16 {
            let mut d = synth(None, &[]);
            set_u16(&mut d, 38, tot);
            assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch), "{tot}");
            if tot > 0 {
                // A protected area of 1..=3 bytes, announced consistently.
                let mut d = header_bytes(32, tot, 4);
                d.extend_from_slice(&[0; 4]);
                d.extend_from_slice(&TLV_PROT_INFO_MAGIC.to_le_bytes());
                d.extend_from_slice(&tot.to_le_bytes());
                d.extend(area_bytes(TLV_INFO_MAGIC, &[]));
                assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch), "{tot}");
            }
        }
        // A TLV header, or a value, running past its area.
        let mut d = synth(None, &[(IMAGE_TLV_SHA256, &[0; 32])]);
        set_u16(&mut d, 38, 4 + 3);
        assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch));
        let mut d = synth(None, &[(IMAGE_TLV_SHA256, &[0; 32])]);
        set_u16(&mut d, 42, 33);
        assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch));
        assert_eq!(synth(None, &[]).len(), 40);
        assert!(
            Image::parse(&synth(None, &[]))
                .unwrap()
                .tlvs()
                .next()
                .is_none()
        );
    }

    #[test]
    fn header_below_32_is_header_too_small() {
        let good = synth(None, &[]);
        for hdr_size in 0..32u16 {
            let mut d = good.clone();
            set_u16(&mut d, 8, hdr_size);
            assert_eq!(
                Image::parse(&d),
                Err(ParseError::HeaderTooSmall),
                "{hdr_size}"
            );
            assert_eq!(
                Header::parse(&d),
                Err(ParseError::HeaderTooSmall),
                "{hdr_size}"
            );
        }
        assert!(Image::parse(&good).is_ok());
        // A larger header than the struct is fine; the extra bytes are not read.
        let mut d = header_bytes(40, 0, 4);
        d.extend_from_slice(&[0xEE; 8 + 4]);
        d.extend(area_bytes(TLV_INFO_MAGIC, &[]));
        assert_eq!(Image::parse(&d).unwrap().hashed_range(), 0..44);
    }

    #[test]
    fn size_overflow_is_reported() {
        // hdr_size + img_size overflows.
        let mut d = synth(None, &[]);
        set_u32(&mut d, 12, u32::MAX - 31);
        let header = Header::parse(&d).unwrap();
        assert_eq!(header.tlv_offset(), Err(ParseError::SizeOverflow));
        assert_eq!(header.hashed_len(), Err(ParseError::SizeOverflow));
        assert_eq!(Image::parse(&d), Err(ParseError::SizeOverflow));
        // hdr_size + img_size fits, + protect_tlv_size does not.
        let mut d = synth(None, &[]);
        set_u32(&mut d, 12, u32::MAX - 32);
        set_u16(&mut d, 10, 1);
        let header = Header::parse(&d).unwrap();
        assert_eq!(header.tlv_offset(), Ok(u32::MAX));
        assert_eq!(header.hashed_len(), Err(ParseError::SizeOverflow));
        assert_eq!(Image::parse(&d), Err(ParseError::SizeOverflow));
        // The unprotected area's end overflows (only reachable through parse_parts: the
        // input would have to be 4 GiB).
        let mut d = synth(None, &[]);
        set_u32(&mut d, 12, u32::MAX - 32 - 3);
        let header = Header::parse(&d).unwrap();
        let tlvs = area_bytes(TLV_INFO_MAGIC, &[(IMAGE_TLV_SHA256, &[0; 32])]);
        assert_eq!(
            Image::parse_parts(header, &tlvs),
            Err(ParseError::SizeOverflow)
        );
        // In range, the offsets are plain sums.
        let header = Header::parse(&synth(None, &[])).unwrap();
        assert_eq!(header.tlv_offset(), Ok(36));
        assert_eq!(header.hashed_len(), Ok(36));
    }

    #[test]
    fn unknown_and_reserved_tlvs_are_yielded_not_errors() {
        let odd: &[(u16, &[u8])] = &[
            (0x00A0, b"ncs"),
            (0x4BA4, b"reserved"),
            (0xFFFE, b""),
            (0x0099, &[1, 2, 3, 4, 5]),
            (0x4BAF, b"x"),
            (IMAGE_TLV_SHA384, &[0; 48]),
        ];
        let d = synth(Some(odd), odd);
        let image = Image::parse(&d).unwrap();
        assert_in_bounds(&d, &image);
        let kinds: Vec<(bool, TlvKind)> = image.tlvs().map(|t| (t.protected, t.kind())).collect();
        let expected = [
            TlvKind::Unknown(0x00A0),
            TlvKind::KeelsignReserved(0x4BA4),
            TlvKind::Unknown(0xFFFE),
            TlvKind::Unknown(0x0099),
            TlvKind::KeelsignReserved(0x4BAF),
            TlvKind::Sha384,
        ];
        let both: Vec<(bool, TlvKind)> = expected
            .iter()
            .map(|k| (true, *k))
            .chain(expected.iter().map(|k| (false, *k)))
            .collect();
        assert_eq!(kinds, both);
        for (tlv, (t, v)) in image.unprotected().iter().zip(odd) {
            assert_eq!(tlv.as_pair(), (*t, *v));
            assert_eq!(<(u16, &[u8])>::from(tlv), (*t, *v));
        }
        // Every type maps to exactly one kind; the named ones round-trip.
        let named = [
            (IMAGE_TLV_KEYHASH, TlvKind::KeyHash),
            (IMAGE_TLV_PUBKEY, TlvKind::PubKey),
            (IMAGE_TLV_SHA256, TlvKind::Sha256),
            (IMAGE_TLV_SHA384, TlvKind::Sha384),
            (IMAGE_TLV_SHA512, TlvKind::Sha512),
            (IMAGE_TLV_RSA2048_PSS, TlvKind::Rsa2048Pss),
            (IMAGE_TLV_ECDSA_SIG, TlvKind::EcdsaSig),
            (IMAGE_TLV_RSA3072_PSS, TlvKind::Rsa3072Pss),
            (IMAGE_TLV_ED25519, TlvKind::Ed25519),
            (IMAGE_TLV_SIG_PURE, TlvKind::SigPure),
            (IMAGE_TLV_DEPENDENCY, TlvKind::Dependency),
            (IMAGE_TLV_SEC_CNT, TlvKind::SecCnt),
            (IMAGE_TLV_BOOT_RECORD, TlvKind::BootRecord),
            (TLV_KEELSIGN_KEY_ID, TlvKind::KeelsignKeyId),
            (TLV_MLDSA44_SIG, TlvKind::MlDsa44Sig),
            (TLV_MLDSA65_SIG, TlvKind::MlDsa65Sig),
            (TLV_LMS_HSS_SIG, TlvKind::LmsHssSig),
        ];
        for t in 0..=u16::MAX {
            let kind = TlvKind::of(t);
            match named.iter().find(|(n, _)| *n == t) {
                Some((_, k)) => assert_eq!(kind, *k),
                None if KEELSIGN_TLV_RANGE.contains(&t) => {
                    assert_eq!(kind, TlvKind::KeelsignReserved(t))
                }
                None => assert_eq!(kind, TlvKind::Unknown(t)),
            }
        }
        // The MCUboot values (image.h:99-121 at a8ffd2c).
        assert_eq!(
            named.map(|(t, _)| t)[..13],
            [
                0x01, 0x02, 0x10, 0x11, 0x12, 0x20, 0x22, 0x23, 0x24, 0x25, 0x40, 0x50, 0x60
            ]
        );
    }

    #[test]
    fn tlv_order_does_not_matter() {
        fn permutations(items: &[usize]) -> Vec<Vec<usize>> {
            if items.len() <= 1 {
                return vec![items.to_vec()];
            }
            let mut out = Vec::new();
            for i in 0..items.len() {
                let mut rest = items.to_vec();
                let first = rest.remove(i);
                for mut p in permutations(&rest) {
                    p.insert(0, first);
                    out.push(p);
                }
            }
            out
        }
        for name in [
            "keelsign-hybrid-ed25519-lms.bin",
            "keelsign-dual-pq-invalid.bin",
            "keelsign-lms-protected-tlvs.bin",
        ] {
            let data = fixture(name);
            let image = Image::parse(data).unwrap();
            let tlvs: Vec<(u16, &[u8])> = image.unprotected().pairs().collect();
            let set: BTreeSet<(u16, &[u8])> = tlvs.iter().copied().collect();
            let selected = select_pq_signature(image.unprotected().pairs());
            let head = &data[range(image.hashed_range())];
            let orders = permutations(&(0..tlvs.len()).collect::<Vec<_>>());
            assert!(orders.len() >= 6);
            for order in orders {
                let reordered: Vec<(u16, &[u8])> = order.iter().map(|&i| tlvs[i]).collect();
                let mut d = head.to_vec();
                d.extend(area_bytes(TLV_INFO_MAGIC, &reordered));
                let image = Image::parse(&d).unwrap();
                let got: Vec<(u16, &[u8])> = image.unprotected().pairs().collect();
                assert_eq!(got, reordered, "{name}");
                assert_eq!(got.iter().copied().collect::<BTreeSet<_>>(), set, "{name}");
                assert_eq!(select_pq_signature(image.unprotected().pairs()), selected);
            }
        }
    }

    #[test]
    fn parse_parts_matches_parse() {
        for (name, data) in all_valid() {
            let header = Header::parse(data).unwrap();
            let tlv_off = header.tlv_offset().unwrap() as usize;
            let whole = Image::parse(data).unwrap();
            let parts = Image::parse_parts(header, &data[tlv_off..]).unwrap();
            assert_eq!(parts, whole, "{name}");
            assert_eq!(parts.hashed_range(), whole.hashed_range(), "{name}");
            assert_eq!(parts.tlv_end(), whole.tlv_end(), "{name}");
            assert!(parts.tlvs().eq(whole.tlvs()), "{name}");
            assert_eq!(
                parts.protected().map(TlvArea::range),
                whole.protected().map(TlvArea::range)
            );
            // And the errors agree on a damaged TLV area.
            let mut d = data.to_vec();
            d[tlv_off] ^= 0x01;
            assert_eq!(
                Image::parse_parts(header, &d[tlv_off..]),
                Image::parse(&d),
                "{name}"
            );
            assert!(Image::parse(&d).is_err());
        }
        let info = TlvInfo::parse(&[0x07, 0x69, 0x0C, 0x00, 0xFF]).unwrap();
        assert_eq!(
            info,
            TlvInfo {
                magic: TLV_INFO_MAGIC,
                tlv_tot: 12
            }
        );
        assert_eq!(
            TlvInfo::parse(&[0x07, 0x69, 0x0C]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn parse_parts_rejects_hand_built_small_header() {
        let d = synth(None, &[(IMAGE_TLV_SHA256, &[0; 32])]);
        let good = Header::parse(&d).unwrap();
        let tlv_bytes = &d[36..];
        assert!(Image::parse_parts(good, tlv_bytes).is_ok());
        for hdr_size in 0..32u16 {
            // Header fields are public: a Header that Header::parse would refuse.
            let header = Header { hdr_size, ..good };
            assert_eq!(
                Image::parse_parts(header, tlv_bytes),
                Err(ParseError::HeaderTooSmall),
                "{hdr_size}"
            );
        }
        // Checked before anything else, even with TLV bytes that are not a TLV area.
        let header = Header {
            hdr_size: 0,
            ..good
        };
        assert_eq!(
            Image::parse_parts(header, &[]),
            Err(ParseError::HeaderTooSmall)
        );
        let header = Header {
            hdr_size: 31,
            img_size: u32::MAX,
            ..good
        };
        assert_eq!(
            Image::parse_parts(header, tlv_bytes),
            Err(ParseError::HeaderTooSmall)
        );
    }

    #[test]
    fn protected_keelsign_pq_tlv_is_ignored_for_selection() {
        let key_id = [0x11; 16];
        let lms = [0x33; 64];
        let protected_sig = [0x44; 100];
        let d = synth(
            Some(&[(TLV_MLDSA44_SIG, &protected_sig)]),
            &[(TLV_KEELSIGN_KEY_ID, &key_id), (TLV_LMS_HSS_SIG, &lms)],
        );
        let image = Image::parse(&d).unwrap();
        assert_in_bounds(&d, &image);

        // tlvs() yields every TLV, the protected ML-DSA-44 one first.
        let all: Vec<(bool, u16, &[u8])> = image
            .tlvs()
            .map(|t| (t.protected, t.tlv_type, t.value))
            .collect();
        assert_eq!(
            all,
            [
                (true, TLV_MLDSA44_SIG, &protected_sig[..]),
                (false, TLV_KEELSIGN_KEY_ID, &key_id[..]),
                (false, TLV_LMS_HSS_SIG, &lms[..]),
            ]
        );
        // The protected PQ TLV lies inside the hashed bytes M.
        let base = d.as_ptr() as usize;
        let at = image.tlvs().next().unwrap().value.as_ptr() as usize - base;
        assert!(range(image.hashed_range()).contains(&at));

        // Selection over the unprotected area ignores it.
        let selected = select_pq_signature(image.unprotected().pairs()).unwrap();
        assert_eq!(selected.algorithm, Algorithm::LmsHss);
        assert_eq!(selected.key_id, key_id);
        assert_eq!(selected.signature, lms);
        // Feeding every TLV instead would see two PQ signatures.
        assert_eq!(
            select_pq_signature(image.tlvs().map(|t| t.as_pair())),
            Err(Error::MultiplePqSignatures)
        );
    }

    #[test]
    fn protected_tlv_spilling_past_prot_end_is_length_mismatch() {
        let unprot = area_bytes(TLV_INFO_MAGIC, &[(IMAGE_TLV_SHA256, &[0; 32])]);
        // A protected area of `tot` bytes (announced consistently by the header and the
        // info header) holding `tlvs`, then the unprotected area.
        let image = |tot: u16, tlvs: &[u8]| {
            let mut d = header_bytes(32, tot, 4);
            d.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            d.extend_from_slice(&TLV_PROT_INFO_MAGIC.to_le_bytes());
            d.extend_from_slice(&tot.to_le_bytes());
            d.extend_from_slice(tlvs);
            d.extend_from_slice(&unprot);
            d
        };
        let sec_cnt = [0x50, 0x00, 4, 0, 7, 0, 0, 0];
        let good = image(12, &sec_cnt);
        assert!(Image::parse(&good).is_ok());

        // The SEC_CNT value runs past prot_end, into the unprotected info header.
        for len in [5u16, 8, 8 + 36] {
            let mut d = good.clone();
            set_u16(&mut d, 42, len);
            assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch), "{len}");
            assert_eq!(oracle(&d).map(|_| ()), Err(ParseError::LengthMismatch));
        }
        // 1 to 3 bytes left over before prot_end: a TLV header that cannot fit.
        for extra in 1..=3u16 {
            let mut tlvs = sec_cnt.to_vec();
            tlvs.resize(tlvs.len() + usize::from(extra), 0);
            let d = image(12 + extra, &tlvs);
            assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch), "{extra}");
            assert_eq!(oracle(&d).map(|_| ()), Err(ParseError::LengthMismatch));
        }
        // A protected TLV header straddling prot_end.
        let d = image(6, &[0x50, 0x00]);
        assert_eq!(Image::parse(&d), Err(ParseError::LengthMismatch));
    }

    #[test]
    fn every_parse_error_variant_is_reachable_and_distinct() {
        // One input per variant. The match is exhaustive, so a new variant needs a case.
        fn case(e: ParseError) -> Vec<u8> {
            let mut d = synth(
                Some(&[(IMAGE_TLV_SEC_CNT, &[7, 0, 0, 0])]),
                &[(IMAGE_TLV_SHA256, &[0; 32])],
            );
            match e {
                ParseError::BadMagic => d[3] = 0x97,
                ParseError::Truncated => {
                    d.pop();
                }
                ParseError::HeaderTooSmall => set_u16(&mut d, 8, 31),
                ParseError::SizeOverflow => set_u32(&mut d, 12, u32::MAX),
                ParseError::BadTlvInfoMagic => set_u16(&mut d, 36, TLV_INFO_MAGIC),
                ParseError::ProtectedSizeMismatch => set_u16(&mut d, 38, 13),
                ParseError::LengthMismatch => set_u16(&mut d, 50, 3),
                ParseError::PqSignatureTooLong => {
                    d = synth(None, &[(TLV_LMS_HSS_SIG, &[0; MAX_PQ_SIGNATURE_LEN + 1])])
                }
            }
            d
        }
        let all = [
            ParseError::BadMagic,
            ParseError::Truncated,
            ParseError::HeaderTooSmall,
            ParseError::SizeOverflow,
            ParseError::BadTlvInfoMagic,
            ParseError::ProtectedSizeMismatch,
            ParseError::LengthMismatch,
            ParseError::PqSignatureTooLong,
        ];
        let mut messages = BTreeSet::new();
        for e in all {
            let d = case(e);
            assert_eq!(Image::parse(&d), Err(e), "{e:?}");
            assert_eq!(oracle(&d).map(|_| ()), Err(e), "{e:?}");
            let message = e.to_string();
            assert!(!message.is_empty());
            messages.insert(message);
            let as_error: &dyn core::error::Error = &e;
            assert!(as_error.source().is_none());
        }
        assert_eq!(messages.len(), all.len(), "Display strings are distinct");
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| a != b), "{a:?} is listed twice");
        }
    }

    #[test]
    fn image_types_are_small() {
        use core::mem::size_of;
        assert_eq!(size_of::<ParseError>(), 1);
        assert_eq!(size_of::<ImageVersion>(), 8);
        assert!(size_of::<Header>() <= 24, "{}", size_of::<Header>());
        assert!(size_of::<TlvKind>() <= 4, "{}", size_of::<TlvKind>());
        assert!(size_of::<Tlv<'_>>() <= 3 * size_of::<usize>());
        assert!(size_of::<TlvArea<'_>>() <= 4 * size_of::<usize>());
        assert!(
            size_of::<Image<'_>>() <= 12 * size_of::<usize>(),
            "{}",
            size_of::<Image<'_>>()
        );
    }

    #[test]
    fn image_flags_expose_mcuboot_bits() {
        assert_eq!(
            [
                IMAGE_F_PIC,
                IMAGE_F_ENCRYPTED_AES128,
                IMAGE_F_ENCRYPTED_AES256,
                IMAGE_F_NON_BOOTABLE,
                IMAGE_F_RAM_LOAD,
                IMAGE_F_ROM_FIXED,
                IMAGE_F_COMPRESSED_LZMA1,
                IMAGE_F_COMPRESSED_LZMA2,
                IMAGE_F_COMPRESSED_ARM_THUMB_FLT,
            ],
            [0x1, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x400, 0x800]
        );
        let none = ImageFlags(0);
        assert!(!none.is_encrypted() && !none.is_compressed() && !none.non_bootable());
        assert!(!none.ram_load() && !none.rom_fixed());
        assert_eq!(none.unknown_bits(), 0);
        assert!(ImageFlags(IMAGE_F_ENCRYPTED_AES256).is_encrypted());
        assert!(ImageFlags(IMAGE_F_COMPRESSED_LZMA1).is_compressed());
        assert!(ImageFlags(IMAGE_F_NON_BOOTABLE).non_bootable());
        assert!(ImageFlags(IMAGE_F_RAM_LOAD).ram_load());
        assert!(ImageFlags(IMAGE_F_ROM_FIXED).rom_fixed());
        assert_eq!(ImageFlags(u32::MAX).unknown_bits(), !0xF3D);
        // Flags are parsed, never acted on (SHA-46).
        let mut d = synth(None, &[]);
        set_u32(&mut d, 16, u32::MAX);
        assert_eq!(
            Image::parse(&d).unwrap().header().flags,
            ImageFlags(u32::MAX)
        );
        // Constants from image.h at a8ffd2c.
        assert_eq!(IMAGE_MAGIC, 0x96f3_b83d);
        assert_eq!((TLV_INFO_MAGIC, TLV_PROT_INFO_MAGIC), (0x6907, 0x6908));
        assert_eq!(
            (IMAGE_HEADER_SIZE, TLV_INFO_SIZE, TLV_HEADER_SIZE),
            (32, 4, 4)
        );
    }

    // ---- Property tests ---------------------------------------------------------------

    /// A header with the image magic and small sizes, then (sometimes) TLV info magics,
    /// then random bytes: inputs that get past the header checks.
    fn magic_prefixed() -> impl Strategy<Value = Vec<u8>> {
        (
            prop_oneof![Just(32u16), 0u16..96],
            0u32..64,
            prop_oneof![Just(0u16), 0u16..64],
            any::<bool>(),
            0u16..160,
            pvec(any::<u8>(), 0..1024),
        )
            .prop_map(|(hdr_size, img_size, prot, with_prot, unprot_tot, tail)| {
                let mut d = header_bytes(hdr_size, prot, img_size);
                let body = usize::from(hdr_size.max(32)) - 32 + img_size as usize;
                d.extend(tail.iter().cycle().take(body));
                if with_prot {
                    d.extend_from_slice(&TLV_PROT_INFO_MAGIC.to_le_bytes());
                    d.extend_from_slice(&prot.to_le_bytes());
                    d.extend(tail.iter().take(usize::from(prot.saturating_sub(4))));
                }
                d.extend_from_slice(&TLV_INFO_MAGIC.to_le_bytes());
                d.extend_from_slice(&unprot_tot.to_le_bytes());
                d.extend(tail);
                d
            })
    }

    fn check_any(bytes: &[u8]) {
        let result = Image::parse(bytes);
        // The error, or on Ok the TLV list (area, type, value offset and length), the
        // hashed range end and tlv_end, all match the oracle's walk.
        assert_eq!(summary(bytes), oracle(bytes));
        if let Ok(image) = result {
            assert_in_bounds(bytes, &image);
            for tlv in image.tlvs() {
                let _ = tlv.kind();
            }
        }
        let _ = Header::parse(bytes);
        let _ = TlvInfo::parse(bytes);
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(
            bytes in prop_oneof![pvec(any::<u8>(), 0..8192), magic_prefixed()]
        ) {
            check_any(&bytes);
        }

        #[test]
        fn mutated_golden_images_error_or_yield_in_bounds_tlvs(
            which in 0usize..11,
            edits in pvec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in proptest::option::of(any::<prop::sample::Index>()),
        ) {
            let (_, data) = all_valid().nth(which).unwrap();
            let mut d = data.to_vec();
            for (at, byte) in edits {
                let i = at.index(d.len());
                d[i] = byte;
            }
            if let Some(cut) = cut {
                d.truncate(cut.index(d.len() + 1));
            }
            check_any(&d);
            if let Ok(image) = Image::parse(&d) {
                prop_assert!(image.hashed_range().end <= image.tlv_end());
                prop_assert!(image.tlv_end() as usize <= d.len());
            }
        }
    }
}
