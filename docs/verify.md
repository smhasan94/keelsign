# Verifying images (SHA-53)

`keelsign verify` checks an MCUboot image against trusted public keys under a device
policy, exactly as a device running `keelsign-verify` would, and says why when it does
not verify. Signing and `inspect` are in [signing.md](signing.md); key files in
[keys.md](keys.md); the policies and image rules in [policy.md](policy.md); the image
format in [image-format.md](image-format.md). The CLI is pre-release.

## Commands

```sh
keelsign verify --pub FILE [--pub FILE ...] [--policy classical|pq|hybrid] [--cnsa-2.0] IMAGE
```

- `--pub`: a trusted public key file (see [Public key files](#public-key-files)). Repeat
  it for several keys: up to 8 post-quantum keys (ML-DSA-44, ML-DSA-65, HSS/LMS, mixed)
  and up to 8 Ed25519 keys. At least one is required.
- `--policy`: which signatures the image must carry (see
  [Policies and inference](#policies-and-inference)). Without it the policy is inferred
  from the keys.
- `--cnsa-2.0`: verify under the strict CNSA 2.0 backend (see [CNSA 2.0](#cnsa-20)).
- `IMAGE`: the MCUboot image. Bytes after its TLV area are ignored (see
  [Padded images](#padded-images)).

For example, after [the README quickstart](../README.md#quickstart)'s `sign`:

```sh
keelsign pubkey --key signing.pem --out signing.pub.pem
keelsign verify --pub signing.pub.pem app.keelsign.bin
```

## Public key files

`--pub` reads an X.509 `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7), PEM label
`PUBLIC KEY` or DER; the format is detected from the contents, and text before a PEM
header is ignored, but text after the PEM footer is refused as a corrupt key file (exit
5). `keelsign pubkey` writes these files (PEM or DER), and so does
`imgtool getpub -e pem` for an Ed25519 key.

| Algorithm | OID | ASN.1 name | `subjectPublicKey` BIT STRING holds | Source |
|---|---|---|---|---|
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` | `id-ml-dsa-44` | the FIPS 204 public key, 1,312 bytes | RFC 9881 |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` | `id-ml-dsa-65` | the FIPS 204 public key, 1,952 bytes | RFC 9881 |
| Ed25519 | `1.3.101.112` | `id-Ed25519` | the 32-byte public key | RFC 8410 |
| HSS/LMS | `1.2.840.113549.1.9.16.3.17` | `id-alg-hss-lms-hashsig` | the DER `OCTET STRING` of the HSS public key `u32 L \|\| LMS public key` (52 or 60 bytes) | RFC 8708 |

The `AlgorithmIdentifier` parameters must be absent for all four. A file is refused
with exit 5 if it is not a PEM or DER `SubjectPublicKeyInfo`, names another OID (the
message lists the four above), has parameters, has a key of the wrong length (for
HSS/LMS: not 52 or 60 bytes, or an unknown LMS typecode), or is a private key
(`PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`; `verify` never reads private keys). Giving the
same key twice, or more than 8 keys of a kind, is a usage error (exit 2). There is no
raw or hex key input.

**The HSS/LMS wrapping.** RFC 8708 §4 defines `HSS-LMS-HashSig-PublicKey ::= OCTET
STRING` and carries it in the `subjectPublicKey` BIT STRING. keelsign reads the RFC 5912
`PUBLIC-KEY` convention: the BIT STRING holds the DER encoding of that OCTET STRING
(`04 3c` and the 60-byte key, for an `m = 32` key), not the raw key. Some implementations
put the raw key straight in the BIT STRING; keelsign refuses that form (exit 5, "not a
DER OCTET STRING") rather than guess. keelsign's own LMS/HSS keys (`keygen --alg
lms-sha256-m32-h10|h15|h20`, SHA-67) are written in the first form by `pubkey`
([keys.md](keys.md#lmshss-keys)); accepting the second form is a follow-up.

## Policies and inference

| `--policy` | `keelsign_verify::Policy` | Ed25519 half | Post-quantum half | Keys needed |
|---|---|---|---|---|
| `classical` | `ClassicalOnly` | required | not checked | an Ed25519 `--pub` |
| `pq` | `PqOnly` | not checked | required | a post-quantum `--pub` |
| `hybrid` | `Hybrid` | required | required | both |

Without `--policy`, the policy is inferred from the keys given: post-quantum keys only
→ `pq`; Ed25519 keys only → `classical`; both → `hybrid`. The output then says
`(inferred from the keys given)`. A `--policy` that needs a kind of key no `--pub` gives
is a usage error (exit 2), for example `--policy hybrid needs an Ed25519 key given with
--pub`.

The policy is the device's decision, never the image's: a hybrid image verifies under
all three, a post-quantum-only image only under `pq`, an imgtool Ed25519 image only
under `classical`.

## What is checked

`verify` runs `keelsign_verify::verify_with`, the same function the device runs, on the
image file: the image rules (flags, keelsign TLVs only in the unprotected area, no
`SIG_PURE`, exactly one 32-byte `SHA256` TLV, `SEC_CNT`), the image digest `M`, then the
halves the policy requires, in the order of
[policy.md](policy.md#error-precedence). The key set is the `--pub` keys:
post-quantum keys are looked up by key ID, Ed25519 keys by KEYHASH
([image-format.md](image-format.md#key-id)). With `--cnsa-2.0` it is
`verify_with(&DefaultBackend::cnsa_2_0(), ..)`, otherwise
`verify_with(&DefaultBackend::new(), ..)`.

`keelsign/tests/verify.rs` checks that the command's exit code and message are the
library's verdict on every image in `tests/fixtures/images/MANIFEST.json` under every
policy, and that the verdict is the manifest's (the matrix in
[policy.md](policy.md)).

Classical verification is Ed25519 only: an image imgtool signed with RSA-2048 or
ECDSA P-256 is not verified under `classical` (exit 9, "no ED25519 signature TLV").
Anti-rollback is not checked: `verify` prints the version and security counter for you
to compare.

## Output

On success `verify` exits 0 and prints, on standard output (here for the fixture
`keelsign-hybrid-ed25519-mldsa44.bin` with its two test keys):

```text
verified: app.keelsign.bin
policy: hybrid (inferred from the keys given)
version: 1.2.3+4
security counter: none
image digest: e72878a8fe7374ccc97aec1ffab2f5642747b63a298bc2699ffdf6fefa9c09c1
pq key: ml-dsa-44 9a24dd433a22a6b1ff7209041aac49ba
ed25519 key: 15bd85175f163ec727380037b5c48ae9f83fc2cb8e12fa5a678be4809f2b3190
```

- `policy:` the policy, with `(inferred from the keys given)` when `--policy` was not
  given.
- `security counter:` the protected `SEC_CNT` value, or `none`.
- `pq key:` the algorithm (`ml-dsa-44`, `ml-dsa-65`, `lms-hss`) and key ID of the key
  that verified the post-quantum half; only when the policy checks it.
- `ed25519 key:` the KEYHASH of the Ed25519 key that verified the classical half; only
  when the policy checks it.
- `image: N bytes (K trailing bytes ignored)`: only when bytes follow the TLV area.

On failure nothing is printed on standard output; the reason goes to standard error:

```text
error: app.keelsign.bin: not verified under policy pq: post-quantum key ID is not in the trusted key set
```

The reason is the `keelsign_verify::Error` message.

## Tampering

Any change to the bytes `M` covers (header, body, protected TLV area) fails the digest
check: `image rule broken: image digest does not match the SHA256 TLV`. A changed
signature fails its half: `post-quantum signature is invalid` (or `is malformed`), or
`Ed25519 half rejected: Ed25519 signature is invalid`. A key that is not trusted:
`post-quantum key ID is not in the trusted key set`, or
`Ed25519 half rejected: KEYHASH is not in the trusted Ed25519 key set`. All exit 9.

## Padded images

Unlike `sign`, `verify` accepts an image followed by padding or a slot trailer, as a
device reads a slot: the bytes after the TLV area are not read, and the output reports
them (`image: 8192 bytes (5877 trailing bytes ignored)`). The trailer is not decoded.

## Key rotation

A device that trusts the old key A and the new key B accepts images signed with either.
`verify` does the same with both keys given:

```sh
keelsign verify --pub a.pub.pem --pub b.pub.pem app-signed-by-b.bin   # exit 0, pq key: ... (B's key ID)
keelsign verify --pub a.pub.pem app-signed-by-b.bin                   # exit 9, key ID not trusted
```

The same holds for two Ed25519 keys under `hybrid` or `classical`.

## CNSA 2.0

`--cnsa-2.0` verifies with `DefaultBackend::cnsa_2_0()`: LMS/HSS under the strict
CNSA 2.0 parameter policy, single-tree LMS only (`L = 1`). A two-level HSS signature and
any ML-DSA signature are refused (exit 9, `unsupported post-quantum parameter set`). It
changes nothing for the Ed25519 half. See
[image-format.md](image-format.md#accepted-lms-parameter-sets-and-cnsa-20) for the
CNSA 2.0 profile.

## Exit codes

The table is final for codes 0 to 9; SHA-67 added 10 and 11 for stateful LMS/HSS keys.
keelsign/src/error.rs assigns these codes, and [keys.md](keys.md#exit-codes) and
[signing.md](signing.md#exit-codes) repeat them.

| Code | Meaning |
|---|---|
| 0 | success; for `verify`, the image is verified under the policy |
| 1 | I/O error (a missing or unreadable image, key or `--pub` file), random-number generator failure, internal error |
| 2 | usage error: bad arguments, an unknown `--policy`, no `--pub`, more than 8 `--pub` keys of a kind, the same key twice, a `--policy` that needs a kind of key no `--pub` gives, an empty passphrase, `OUT` is `IN` or a key file |
| 3 | the output file exists and `--force` was not given |
| 4 | passphrase: wrong, missing or unexpected |
| 5 | corrupt or unsupported key file, private or public (for `--pub`: not a `SubjectPublicKeyInfo`, an unknown OID, parameters present, the wrong length, a private key) |
| 6 | a key of the wrong kind (`--alg`, `sign --key`, `--hybrid-key`) (or, for an LMS/HSS key, a different height than the `lms-sha256-m32-hNN` value) |
| 7 | the image is rejected as malformed (`verify`, `inspect`, `sign`): not an MCUboot image or larger than 64 MiB; for `sign` also an image rule broken or bytes after the TLV area |
| 8 | `sign`: the image already carries keelsign TLVs (or, with `--hybrid-key`, an Ed25519 pair) and `--replace` was not given |
| 9 | `verify`: the image is not verified under the policy: a signature invalid or malformed, a key not trusted, a TLV missing or repeated, the Ed25519 half rejected, an image rule broken (including a digest mismatch), an unsupported parameter set |
| 10 | `sign` with an LMS/HSS key: its state is refused: the state file or journal is missing, the state file belongs to another key, is behind the journal (restored from a copy: retire the key), or is corrupt, or another keelsign process holds the key's lock (see [keys.md](keys.md#stateful-lms-keys)) |
| 11 | `sign` with an LMS/HSS key: `LeafIndexExhausted`, every leaf of the key is used; generate a new key |

How the verifier's errors map: `Parse`, `Read` and `TlvAreaTooLarge` (the image does not
parse) are 7; `ChunkBufferEmpty` (a misuse of the verifier) is 1; every other
`keelsign_verify::Error`, including any added later, is 9. The ticket's "signature
failure" class is 9 rather than 1, because 1 already means an I/O error. Error messages
go to standard error, start with `error:` and name the file.

## imgtool interoperability

`keelsign/tests/imgtool.rs` runs against MCUboot's imgtool 2.4.0 (CI installs it; locally
the tests are ignored unless imgtool is on `PATH`, see
[signing.md](signing.md#interoperability-checks)):

- an image `imgtool sign` signed with a keelsign Ed25519 key verifies with
  `keelsign verify --policy classical`, trusting either `keelsign pubkey`'s or
  `imgtool getpub -e pem`'s public key file; a flipped body byte fails both
  `keelsign verify` (exit 9) and `imgtool verify`;
- imgtool's RSA-2048 and ECDSA P-256 images are not verified under `classical`
  (exit 9), and an RSA public key file is refused (exit 5);
- a `keelsign sign --hybrid-key` image validates with `imgtool verify` and verifies with
  `keelsign verify` under `hybrid` and `classical`.
