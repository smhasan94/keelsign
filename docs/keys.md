# Keys and key files (SHA-49)

`keelsign keygen` creates signing keys and `keelsign pubkey` exports their public keys.
This page fixes the file formats, the algorithm OIDs, passphrase encryption, the key
identifiers printed, file permissions and the exit codes. The CLI is pre-release: image
signing (`sign`) and `inspect` are in [signing.md](signing.md); `verify` is not written
yet (SHA-53). LMS/HSS keys are stateful and come with their own key files later (E7.2).

## Commands

```sh
keelsign keygen --alg ml-dsa-44|ml-dsa-65|ed25519 --out FILE [--format pem|der]
                [--passphrase-file PATH | --passphrase-env VAR] [--force]
keelsign pubkey --key FILE [--alg ml-dsa-44|ml-dsa-65|ed25519] [--out FILE]
                [--format pem|der] [--passphrase-file PATH | --passphrase-env VAR] [--force]
```

`keygen` writes a new private key to `--out` and prints its algorithm, its key ID or
KEYHASH and the file it wrote:

```text
$ keelsign keygen --alg ml-dsa-44 --out signing.pem
algorithm: ml-dsa-44
key id: 1f3c...  (32 hex digits)
private key: signing.pem (PKCS#8 PEM, not encrypted)
```

The private key is only ever written to the file, never to standard output.

`pubkey` reads a private key file and writes its public key to `--out`, or as PEM to
standard output (`--format der` needs `--out`). It prints `algorithm:` and the
`key id:` / `keyhash:` line to standard error. With `--alg` it fails (exit code 6) if
the key is of a different algorithm.

```sh
keelsign pubkey --key signing.pem --out signing.pub.pem
keelsign pubkey --key signing.pem --alg ml-dsa-44 > signing.pub.pem
```

## Algorithms and OIDs

| `--alg` | OID | ASN.1 name | Source |
|---|---|---|---|
| `ml-dsa-44` | `2.16.840.1.101.3.4.3.17` | `id-ml-dsa-44` | NIST CSOR `sigAlgs 17` (`sigAlgs ::= { nistAlgorithms 3 }`); RFC 9881 §2 |
| `ml-dsa-65` | `2.16.840.1.101.3.4.3.18` | `id-ml-dsa-65` | NIST CSOR `sigAlgs 18`; RFC 9881 §2 |
| `ed25519` | `1.3.101.112` | `id-Ed25519` | RFC 8410 §3 |

The same OID identifies the private key and the public key. The `AlgorithmIdentifier`
`parameters` field is absent for all three (RFC 9881 §2: MUST be absent; RFC 8410 §3:
absent); a key file with parameters present, even `NULL`, is rejected. ML-DSA-87 and
LMS/HSS are not generated: keelsign images use ML-DSA-44/65, and LMS/HSS keys are
stateful (E7.2).

## Private key files

Private keys are PKCS#8 `PrivateKeyInfo` **version 1** (RFC 5208, RFC 5958 §2), PEM
label `PRIVATE KEY` (RFC 7468 §10) or DER with `--format der`. PEM uses LF line endings.

**ML-DSA** keys are stored in the RFC 9881 §6 `seed` form: the `privateKey` OCTET
STRING holds `seed [0] IMPLICIT OCTET STRING (SIZE (32))`, the 32-byte seed ξ of
FIPS 204 `ML-DSA.KeyGen_internal`. RFC 9881 RECOMMENDS this form (§6, §8.1): it is the
smallest and every other form is derived from it. The file is always 54 bytes of DER:

```text
30 34                                  SEQUENCE (52)
   02 01 00                            INTEGER 0 (v1)
   30 0b 06 09 60 86 48 01 65 03 04 03 11   AlgorithmIdentifier { id-ml-dsa-44 }  (12 for ML-DSA-65)
   04 22 80 20 <32-byte seed>          OCTET STRING { [0] seed }
```

**Ed25519** keys use the RFC 8410 §7 layout, version 1, without the optional public
key: `privateKey` holds `CurvePrivateKey ::= OCTET STRING`, the 32-byte secret key.
The file is always 48 bytes of DER:

```text
30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte secret key>
```

Version 1 is deliberate: MCUboot's imgtool (2.4.0) and Python `cryptography` reject the
version 2 encoding with the public key appended (they report extra data), and the same
file must sign keelsign images and plain MCUboot images. This is byte-for-byte the
layout of imgtool's own keys (`tests/fixtures/images/keys/ed25519-test-key.pem`).

What `pubkey` and `sign` read:

- PEM (`PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`; text before the header is ignored, as
  RFC 7468 §2 allows) or DER.
- ML-DSA: the `seed` form only. The RFC 9881 `expandedKey` and `both` forms are refused
  with a message. OpenSSL 3.5+ writes `both` by default (`openssl genpkey -algorithm
  ML-DSA-44`); convert such a key to the seed form with

  ```sh
  openssl pkey -in K.pem -provparam ml-dsa.output_formats=seed-only -out K.seed.pem
  ```

  A PKCS#8 version 2 ML-DSA key's `publicKey` must match the public key derived from
  the seed; otherwise the file is rejected (exit code 5).
- Ed25519: version 1, or version 2 with the public key, which must match the private
  key.

## Public key files

Public keys are X.509 `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7; RFC 9881,
RFC 8410 §4), PEM label `PUBLIC KEY` or DER. The `subjectPublicKey` BIT STRING holds the
FIPS 204 public key encoding (1,312 / 1,952 bytes) or the 32-byte Ed25519 key. Every
file starts with a fixed header:

| Algorithm | DER header (hex) | File length |
|---|---|---|
| ML-DSA-44 | `30820532300b06096086480165030403110382052100` | 1,334 bytes |
| ML-DSA-65 | `308207b2300b0609608648016503040312038207a100` | 1,974 bytes |
| Ed25519 | `302a300506032b6570032100` | 44 bytes |

## Passphrase encryption

With `--passphrase-file` or `--passphrase-env`, `keygen` writes a PKCS#8
`EncryptedPrivateKeyInfo` (RFC 5958 §3), PEM label `ENCRYPTED PRIVATE KEY` or DER,
around the same version 1 `PrivateKeyInfo`:

- PBES2 (`1.2.840.113549.1.5.13`, RFC 8018 §6.2).
- KDF scrypt (`1.3.6.1.4.1.11591.4.11`, RFC 7914 §7) with cost N = 16384 (2^14),
  block size r = 8, parallelization p = 1 and a random 16-byte salt.
- Cipher AES-256-CBC (`2.16.840.1.101.3.4.1.42`) with a random 16-byte IV.

These are the parameters `openssl pkcs8 -topk8 -scrypt` uses, and OpenSSL reads the
files: `openssl pkey -in k.pem -passin file:pw.txt`.

- `--passphrase-file PATH`: the passphrase is the first line of the file, without its
  line terminator (`\n` or `\r\n`), like OpenSSL's `-passin file:`.
- `--passphrase-env VAR`: the passphrase is the value of the environment variable.
- The two are mutually exclusive. An empty passphrase, an unset variable or a variable
  that is not valid Unicode is a usage error (exit code 2).
- There is no `--passphrase VALUE`: a value on the command line is visible to other
  users in the process list and kept in shell history. An interactive prompt is a
  follow-up.
- `pubkey` needs the passphrase exactly when the key is encrypted: a missing passphrase
  for an encrypted key, or a passphrase for an unencrypted key, fails with exit code 4.

AES-CBC has no integrity check, so a wrong passphrase and a corrupted ciphertext look
the same: keelsign reports "wrong passphrase for FILE (or the encrypted key is
corrupt)".

When reading an encrypted key, the KDF parameters come from the file, so keelsign checks
them before deriving anything (a hostile file could otherwise crash the tool or make it
use unbounded memory and time):

- Only PBES2 with scrypt or PBKDF2 and AES-128/192/256-CBC is read. PBES1, AES-GCM and
  other KDFs or ciphers are refused: "unsupported encryption scheme; keelsign reads
  PBES2 (scrypt or PBKDF2 with AES-CBC)" (exit code 5).
- scrypt: N must be a power of two from 2 to 2^20 (1,048,576), 1 ≤ r ≤ 32 and
  1 ≤ p ≤ 16, and 128·r·N ≤ 256 MiB (the memory scrypt needs). keelsign itself writes
  N = 2^14, r = 8, p = 1 (16 MiB), as does `openssl pkcs8 -topk8 -scrypt`.
- PBKDF2: HMAC-SHA-256 as the PRF (what OpenSSL writes) and 1 to 10,000,000
  iterations.
- A parameter outside these ranges is refused with exit code 5, naming the parameter.

The seed, the passphrase and the decoded key documents are held in zeroizing buffers
that are wiped when dropped. Transient copies the cryptography libraries make on the
stack are not wiped; keelsign uses no `unsafe` code to reach them.

## Key ID and KEYHASH

keelsign identifies a post-quantum key by its **key ID** and an Ed25519 key by MCUboot's
**KEYHASH**; `keygen` and `pubkey` print the one that applies.

- ML-DSA: `key id` = the first 16 bytes of SHA-256 over the raw FIPS 204 public key
  encoding, printed as 32 hex digits. This is the value of the `TLV_KEELSIGN_KEY_ID`
  TLV and of `keelsign_verify::key_id_of`; see
  [image-format.md, Key ID](image-format.md#key-id). All 16 bytes are printed; there is
  no shorter 8-byte form (earlier planning notes that mention one are wrong).
- Ed25519: `keyhash` = SHA-256 over the DER `SubjectPublicKeyInfo` (the 44-byte public
  key file), printed as 64 hex digits. This is the value imgtool writes to MCUboot's
  `IMAGE_TLV_KEYHASH` and of `keelsign_verify::keyhash_of`.

Worked examples with published test vectors:

- The RFC 9881 Appendix C.1.1.1 ML-DSA-44 key (seed `00 01 02 … 1f`) has the public key
  of Appendix C.2 and `key id: 9f107644c1084526af3bc8098680b054`; the ML-DSA-65 key of
  C.1.2.1 (same seed) has `key id: d666806e11cee19a7c989f7445f90dd4`.
- The RFC 8410 §10.3 Ed25519 key has the public key of §10.1 and
  `keyhash: a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f`.

`keelsign/tests/known_keys.rs` checks these values.

## File permissions and overwriting

- On Linux and macOS a private key file is created with mode `0600` (owner read and
  write only); the umask can only remove bits from that.
- An existing output file (private or public) is never replaced unless `--force` is
  given; without it the command fails with exit code 3 before generating anything, and
  the existing file is left untouched.
- With `--force`, the new file is written to a temporary file in the same directory
  (`.NAME.keelsign-tmp-PID`, mode `0600` for private keys), flushed to disk and renamed
  over the old one. The replaced file never holds a partial key, and an old
  world-readable file is replaced by a `0600` one. If `--out` is a symbolic link, the
  link itself is replaced and its target is left unchanged.
- An interrupted `--force` run (killed, power loss) can leave the temporary file
  `.NAME.keelsign-tmp-PID` behind. It has mode `0600` and may hold the private key:
  delete it. If it is still there when the same process ID comes round again, keelsign
  stops with exit code 1 and says so.
- `pubkey --out` refuses to write to the file given with `--key` (also through a link),
  with exit code 2, so it can never replace the private key with its public key.
- Key files and passphrase files larger than 1 MiB are refused without reading them
  further (exit code 5 for a key file, 2 for a passphrase file).
- A failed write removes the partial file.
- On other platforms (Windows) no access-control change is made; `keygen` prints a note,
  and protecting the file is up to you.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | I/O error (unreadable key or passphrase file, write failure), random-number generator failure, internal error |
| 2 | usage error: unknown command, option or `--alg` value, conflicting options, empty passphrase, passphrase file over 1 MiB, `--format der` without `--out`, `pubkey --out` naming the `--key` file |
| 3 | the output file exists and `--force` was not given |
| 4 | passphrase: wrong, missing for an encrypted key, or given for an unencrypted key |
| 5 | corrupt or unsupported key file (not PEM/DER PKCS#8, over 1 MiB, a public key, an unsupported algorithm, ML-DSA `expandedKey`/`both`, parameters present, a v2 public key that does not match, an unsupported encryption scheme or out-of-range KDF parameters) |
| 6 | the key file holds a different algorithm than `--alg` (for `sign`: `--key` is not ML-DSA or `--hybrid-key` is not Ed25519) |
| 7 | `sign` / `inspect`: the input image is rejected (see [signing.md](signing.md#exit-codes)) |
| 8 | `sign`: the input image already carries keelsign TLVs and `--replace` was not given (see [signing.md](signing.md#exit-codes)) |

Error messages go to standard error, start with `error:` and name the file.

## Checking a key file

Show the structure and the OID:

```sh
openssl asn1parse -in signing.pem
openssl asn1parse -in signing.pub.pem
```

OpenSSL 3.5 or newer prints the names (`ML-DSA-44`, `ML-DSA-65`, `ED25519`); older
OpenSSL and LibreSSL print the dotted OID or `Ed25519`. For an encrypted key,
`asn1parse` shows the PBES2, scrypt and AES-256-CBC OIDs.

Derive the public key with OpenSSL (ML-DSA needs OpenSSL 3.5 or newer) and compare it
with `keelsign pubkey`:

```sh
openssl pkey -in signing.pem -pubout | diff - <(keelsign pubkey --key signing.pem 2>/dev/null)
openssl pkey -in signing.enc.pem -passin file:pw.txt -pubout
```

For an Ed25519 key, imgtool gives the same public key and KEYHASH:

```sh
imgtool getpub -k ed.pem -e pem
imgtool getpubhash -k ed.pem -e raw | xxd -p -c 32
```

These checks are automated in `keelsign/tests/interop.rs` (ignored by default; see the
file for how to run them).
