# Signing and inspecting images (SHA-51)

`keelsign sign` adds a post-quantum signature to an MCUboot image, optionally with
MCUboot's Ed25519 pair (a hybrid image). `keelsign inspect` describes an image as text or
JSON. The image format is specified in [image-format.md](image-format.md); the device
policies in [policy.md](policy.md); key files in [keys.md](keys.md). The CLI is
pre-release: `verify` comes with SHA-53, and LMS/HSS signing with E7.2 (stateful keys).

## Commands

```sh
keelsign sign --key FILE [--hybrid-key FILE] [--replace] [--force]
              [--passphrase-file PATH | --passphrase-env VAR] IN OUT
keelsign inspect [--json] IMAGE
```

- `--key`: an ML-DSA-44 or ML-DSA-65 private key file (`keelsign keygen`, PKCS#8 PEM or
  DER, encrypted or not).
- `--hybrid-key`: an Ed25519 private key file; also add MCUboot's `KEYHASH` + `ED25519`
  pair.
- `--replace`: replace the keelsign TLVs an image already carries (and, with
  `--hybrid-key`, its Ed25519 pair).
- `--force`: replace `OUT` if it exists (written to a temporary file and renamed over
  it).
- `--passphrase-file` / `--passphrase-env`: the passphrase of whichever of `--key` and
  `--hybrid-key` is encrypted (both, if both are encrypted under the same passphrase), as
  in [keys.md](keys.md#passphrase-encryption).

For example, on an image imgtool signed with Ed25519:

```sh
keelsign keygen --alg ml-dsa-65 --out pq.pem
keelsign sign --key pq.pem app.signed.bin app.keelsign.bin
keelsign inspect app.keelsign.bin
```

`sign` prints what it did:

```text
algorithm: ml-dsa-65
key id: 9a24dd433a22a6b1ff7209041aac49ba
image digest: 4eaeaf5d62fb41180444e1679b03c6b489360523d805afc4c5e032b37aac1745
signed: app.keelsign.bin (5648 bytes, +3333 bytes of TLVs)
```

and, for a hybrid image, a `keyhash:` line after the key ID.

## What sign adds

The new TLVs go at the end of the unprotected TLV area, after every MCUboot TLV, in the
order of [image-format.md](image-format.md#hybrid-layout):

| Order | TLV | ID | Value | When |
|---|---|---|---|---|
| 1 | `KEYHASH` | `0x01` | SHA-256 of the Ed25519 key's DER `SubjectPublicKeyInfo` | `--hybrid-key` |
| 2 | `ED25519` | `0x24` | 64-byte RFC 8032 signature over `M` | `--hybrid-key` |
| 3 | keelsign key ID | `0x4BA0` | first 16 bytes of SHA-256 of the FIPS 204 public key | always |
| 4 | ML-DSA-44 / ML-DSA-65 signature | `0x4BA1` / `0x4BA2` | 2,420 / 3,309 bytes | always |

`it_tlv_tot` of the unprotected area is updated; the area must stay within 65,535 bytes.

## What is preserved

- The header, the body and the protected TLV area, byte for byte: `sign` copies
  `0..hdr_size + img_size + protect_tlv_size` verbatim, so the image digest, the version,
  the security counter (`SEC_CNT`), `DEPENDENCY` and `BOOT_RECORD` do not change.
- Every MCUboot TLV in the unprotected area (`SHA256`, an existing `KEYHASH` + signature
  pair from imgtool, vendor TLVs), byte for byte and in order. The `SHA256` TLV is the
  one imgtool wrote; `sign` checks it and never rewrites it.

So an image imgtool signed with Ed25519, RSA or ECDSA keeps validating with `imgtool
verify` and under MCUboot, and gains a post-quantum signature for devices that check
it.

## The image digest M

Both signatures are over the image digest `M`: SHA-256 of header, body and protected TLV
area, which is the value of the image's `SHA256` TLV
([image-format.md](image-format.md#signing-mode)). `sign` recomputes `M` and refuses an
image whose `SHA256` TLV differs. ML-DSA signs `M` in pure mode with the context
`MLDSA_CONTEXT` = `keelsign-mcuboot-image-v1`.

## Hedged ML-DSA signing

ML-DSA signatures are hedged: FIPS 204 `ML-DSA.Sign` with fresh randomness `rnd` from
the operating system's random-number generator (not the deterministic variant). Signing
the same image twice gives two different signatures, and both verify. Compare images by
verifying them, never by their bytes.

## Self-check

Before it writes `OUT`, `sign` verifies the signed image with `keelsign_verify::verify`
(the device code, with the `ml-dsa` and `ed25519` features) under `PqOnly` against the
`--key` public key, and also under `Hybrid` with the `--hybrid-key` public key. If either
fails, `sign` exits with code 1 ("internal error: the signed image does not verify") and
writes nothing.

## Refusals

`sign` checks its input before it reads the keys:

- Not an MCUboot image keelsign reads: bad or big-endian magic, truncated, inconsistent
  sizes (exit 7).
- Bytes after the unprotected TLV area, such as padding or a slot trailer
  (`imgtool sign --pad`): sign before padding; padded images are a follow-up (exit 7).
- An image rule of [policy.md](policy.md) broken: encrypted, compressed or non-bootable
  flag, a keelsign TLV in the protected area, `SIG_PURE`, no or several `SHA256` TLVs
  (a SHA-384- or SHA-512-only image too), a malformed `SEC_CNT`, or a digest that does
  not match the `SHA256` TLV (exit 7). `--replace` does not help: it only edits the
  unprotected area.
- Larger than 64 MiB, or a TLV area that would exceed 65,535 bytes (exit 7).
- Already carries keelsign TLVs (`0x4BA0..=0x4BAF`), or, with `--hybrid-key`, an `ED25519`
  TLV, and `--replace` was not given (exit 8). With `--replace` every unprotected TLV in
  `0x4BA0..=0x4BAF` is removed, and with `--hybrid-key` every `ED25519` TLV and the
  `KEYHASH` immediately before it; other TLVs stay.
- `--key` not ML-DSA, or `--hybrid-key` not Ed25519 (exit 6); `OUT` exists without
  `--force` (exit 3); `OUT` is `IN` or a key file (exit 2).

## Hybrid images

There are two ways to make a hybrid (Ed25519 + ML-DSA) image:

1. Sign with imgtool first (`imgtool sign --key ed25519.pem ...`), then
   `keelsign sign --key pq.pem IN OUT`. The imgtool `KEYHASH` + `ED25519` pair stays
   as it is.
2. Build an unsigned image with imgtool (`imgtool sign` without `--key` writes only the
   `SHA256` TLV), then `keelsign sign --key pq.pem --hybrid-key ed25519.pem IN OUT`. The
   Ed25519 key is a `keelsign keygen --alg ed25519` file, which imgtool also reads, so
   `imgtool verify --key ed25519.pem OUT` validates the result.

Giving `--hybrid-key` for an image that already has an Ed25519 signature is refused
(exit 8) unless `--replace`, which swaps the pair for the new key's.

## inspect

`keelsign inspect IMAGE` prints one `key: value` line per field, with the TLVs in
indented blocks; `keelsign inspect --json IMAGE` prints the same report as JSON. It
reports:

- the file length, `tlv_end` (where the image ends) and the bytes after it
  (`trailing_bytes`: padding or a slot trailer; `inspect` accepts padded images);
- the header fields as stored (magic, load address, sizes, flags, version) and decoded
  (flag names, unknown flag bits, the version string `major.minor.revision+build`);
- the computed digest `M` and whether the `SHA256` TLV matches it (`null` when there is
  no `SHA256` TLV or more than one);
- both TLV areas (info magic, `tlv_tot`) and every TLV: type, hex type, name (`null` for
  unknown types), length, the value in hex (the full value in JSON; the first 16 bytes,
  `…` and the length in the text output for longer values) and, where keelsign knows the
  TLV, a decoded value: hash algorithm and digest match, KEYHASH, the algorithm OID of a
  PUBKEY, the security counter, a dependency's image index and minimum version,
  BOOT_RECORD as CBOR (not decoded), the key ID, the ML-DSA parameter set, and an HSS
  signature's levels `L`, LMS and LM-OTS type names and leaf index `q`;
- the key IDs and keyhashes in the image, and every signature TLV with its kind, area,
  length, the 32-byte `KEYHASH` immediately before it (classical signatures; `paired`
  means a 32-byte `KEYHASH` immediately before it, otherwise `keyhash` is `null` and
  `paired` is `false`) or the image's 16-byte key ID (post-quantum signatures; `null` if
  there are none, several, or one of another length), and the HSS structure.

The output depends only on the image bytes: it never contains the file's path, the time
or the terminal size. A file that is not an MCUboot image exits with code 7. The
snapshots under `keelsign/tests/snapshots/inspect/` are written by
`scripts/gen_inspect_snapshots.py` ([fixtures.md](fixtures.md)).

## JSON schema and stability

[`docs/inspect-schema.json`](inspect-schema.json) is the JSON Schema (Draft 2020-12) of
`inspect --json`. Every object has `additionalProperties: false`, every top-level field
is required, `format` is `"keelsign-inspect"` and `schema_version` is `1`. The keelsign
tests validate the output for every sample image against it.

Stability policy, within a `schema_version`:

- Fields are never removed, renamed or retyped.
- New fields are optional, and the schema is updated in the same change that adds them.
- A breaking change bumps `schema_version`.

Readers should check `schema_version` and ignore fields they do not know.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | I/O error, random-number generator failure, internal error (including a signed image that does not verify) |
| 2 | usage error: bad arguments, empty passphrase, `OUT` is `IN` or a key file |
| 3 | `OUT` exists and `--force` was not given |
| 4 | passphrase: wrong, missing for an encrypted key, or given when neither key is encrypted |
| 5 | corrupt or unsupported key file (as in [keys.md](keys.md#exit-codes)) |
| 6 | `--key` is not an ML-DSA key or `--hybrid-key` is not an Ed25519 key |
| 7 | the input image is rejected: not an MCUboot image, an image rule broken, bytes after the TLV area, larger than 64 MiB, TLV area too large (`verify` and `inspect`: not an MCUboot image or larger than 64 MiB) |
| 8 | the input image already carries keelsign TLVs (or, with `--hybrid-key`, an Ed25519 signature) and `--replace` was not given |
| 9 | `verify`: the image is not verified under the policy (see [verify.md](verify.md#exit-codes)) |

Codes 7 and 8 are provisional until the `verify` command (SHA-53) fixes its own. Error
messages go to standard error, start with `error:` and name the file.

## Interoperability checks

`keelsign/tests/imgtool.rs` runs against MCUboot's imgtool 2.4.0 (CI installs it; locally
the tests are ignored unless imgtool is on `PATH`):

```sh
python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool==2.4.0
PATH="$PWD/.venv-imgtool/bin:$PATH" cargo test -p keelsign --locked --test imgtool -- --ignored
```

They check that `imgtool dumpinfo` reads signed images and lists the key-ID and PQ TLVs
(as `UNKNOWN` vendor TLVs) after every MCUboot TLV, that `imgtool verify` still validates
the Ed25519 half, and that an unsigned imgtool image signed with `--hybrid-key`
validates with `imgtool verify --key` under the keelsign Ed25519 key.

## LMS/HSS

`sign` does not sign with LMS/HSS: LMS/HSS keys are stateful and need their own key
files and state handling (E7.2). `inspect` decodes LMS/HSS signature TLVs (`0x4BA3`)
already, and `--replace` replaces one with an ML-DSA signature.
