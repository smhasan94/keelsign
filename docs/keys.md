# Keys and key files (SHA-49)

`keelsign keygen` creates signing keys and `keelsign pubkey` exports their public keys.
This page fixes the file formats, the algorithm OIDs, passphrase encryption, the key
identifiers printed, file permissions and the exit codes. The CLI is pre-release: image
signing (`sign`) and `inspect` are in [signing.md](signing.md); `verify`, which reads the
public key files below, is in [verify.md](verify.md). LMS/HSS keys (SHA-67) are
stateful: each comes with a state file and a journal, and must be handled by the rules
in [Stateful LMS keys](#stateful-lms-keys).

## Commands

```sh
keelsign keygen --alg ml-dsa-44|ml-dsa-65|ed25519|lms-sha256-m32-h10|lms-sha256-m32-h15|lms-sha256-m32-h20
                [--hss-levels 1|2] --out FILE [--format pem|der]
                [--passphrase-file PATH | --passphrase-env VAR] [--force]
keelsign pubkey --key FILE [--alg ALG] [--out FILE]
                [--format pem|der] [--passphrase-file PATH | --passphrase-env VAR] [--force]
```

`--hss-levels` applies to the LMS/HSS values only (see [LMS/HSS keys](#lmshss-keys)).

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
| `lms-sha256-m32-h10`, `-h15`, `-h20` | `1.2.840.113549.1.9.16.3.17` | `id-alg-hss-lms-hashsig` | RFC 8708 §3 |

The same OID identifies the private key and the public key. The `AlgorithmIdentifier`
`parameters` field is absent for all of them (RFC 9881 §2: MUST be absent; RFC 8410 §3
and RFC 8708 §3: absent); a key file with parameters present, even `NULL`, is rejected.
ML-DSA-87 is not generated: keelsign images use ML-DSA-44/65. `pubkey --alg` with an
LMS/HSS value checks that the key is an LMS/HSS key whose top-level tree has that
height; a key of another height fails with exit code 6, naming both parameter sets.

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

`keelsign verify --pub` reads these files, PEM or DER, and HSS/LMS public keys in the
RFC 8708 form ([verify.md](verify.md#public-key-files)), which `pubkey` writes for
LMS/HSS keys (below).

## LMS/HSS keys

| `--alg` | LMS parameter set (typecode) | Signatures, one level | Signatures, `--hss-levels 2` | Signature, one level | `keygen` time |
|---|---|---|---|---|---|
| `lms-sha256-m32-h10` | LMS_SHA256_M32_H10 (`0x06`) | 1,024 | 1,048,576 | 1,456 bytes | 0.08 s |
| `lms-sha256-m32-h15` | LMS_SHA256_M32_H15 (`0x07`) | 32,768 | 2^30 | 1,616 bytes | 1.6 s |
| `lms-sha256-m32-h20` | LMS_SHA256_M32_H20 (`0x08`) | 1,048,576 | 2^40 | 1,776 bytes | 50 s |

Every level uses LMOTS_SHA256_N32_W8 (`0x04`): SHA-256, n = m = 32, W8, the sets the
keelsign device policies accept (RFC 8554, SP 800-208; [policy.md](policy.md)). The
`keygen` times are one measurement of the release binary on a 12-core Apple M4 Pro
(the H20 tree is 2^20 leaves of 34 Winternitz chains each, computed on every core: 426 s
of CPU time, 50 s wall time; `keygen` prints a note that it takes minutes). A signature
recomputes at most 1,024 leaves, about 0.1 s on the same machine.

- **One level** (the default, `--hss-levels 1`) is a single LMS tree, an HSS key with
  `L = 1`, which CNSA 2.0 allows (`keelsign verify --cnsa-2.0` accepts it).
- **Two levels** (`--hss-levels 2`) give 2^(2h) signatures: top-level leaf `i` signs
  bottom tree `i`, which signs images. keelsign-verify's default policy accepts two
  levels; CNSA 2.0 does not (`verify --cnsa-2.0` exits 9). Both levels have the height
  of `--alg`. Bottom tree 0 is the stored second level; tree `i > 0` is derived from it:
  `SEED_1,i = H(SEED_1 || u32(i) || "keelsign-hss-seed")` and
  `I_1,i = H(I_1 || u32(i) || "keelsign-hss-id")[..16]`, so the key file stays small
  and a new bottom tree is built when signing crosses into it.
- SHA-256/192 (M24) keys, W1/W2/W4 and other heights are not generated (`verify` reads
  them where its policy allows). Neither are more than two levels.
- The one-time keys follow RFC 8554 Appendix A,
  `x_q[i] = H(I || u32(q) || u16(i) || u8(0xff) || SEED)`, and the randomizer `C` of
  each signature is derived the same way with `i = 0xFFFD` (the convention of Cisco's
  hash-sigs reference implementation; RFC 8554 Appendix A specifies only the one-time
  keys), so signing is deterministic. keelsign's own signer is checked against the independent signer hsslms
  0.1.3 (byte-identical public keys and signatures for the fixture cases 301, 302 and
  303) and every signature it writes is verified with keelsign-verify first.

**Private key file.** PKCS#8 version 1, PEM label `PRIVATE KEY` (or DER, or encrypted as
in [Passphrase encryption](#passphrase-encryption)), `AlgorithmIdentifier`
`id-alg-hss-lms-hashsig` with parameters absent, and as `privateKey` keelsign's
private-key blob, version 1 (integers big-endian):

| Field | Bytes | Value |
|---|---|---|
| version | 1 | `01` |
| `L` | 4 | the number of levels, 1 or 2 |
| per level: LMS typecode | 4 | `0x06`, `0x07` or `0x08` |
| per level: LM-OTS typecode | 4 | `0x04` |
| per level: `SEED` | 32 | the tree's secret seed |
| per level: `I` | 16 | the tree's identifier |
| HSS public key | 60 | `u32 L` and the top tree's LMS public key |

The blob is 121 bytes with one level and 177 with two. There is no standard private-key
format for HSS/LMS, so the blob is keelsign's own: other tools do not read it. When it is
loaded, the public key's `L`, typecodes and `I` must match the stored top tree (exit 5
otherwise); its root `T[1]` is not recomputed (that is the whole top tree), but the state
file is bound to the key ID over the public key, and every signed image is verified
against it before it is written.

**Public key file.** `pubkey` writes an RFC 8708 `SubjectPublicKeyInfo` whose
`subjectPublicKey` BIT STRING holds the DER OCTET STRING of the 60-byte HSS public key,
the form `verify --pub` reads ([verify.md](verify.md#public-key-files)). It is always
82 bytes of DER:

```text
3050300d060b2a864886f70d0109100311033f00043c <60-byte HSS public key>
```

The key ID is the first 16 bytes of SHA-256 over the 60-byte HSS public key, as for
ML-DSA keys ([Key ID and KEYHASH](#key-id-and-keyhash)).

`keygen` prints the parameter set, the signature count and the two state files, and a
note on standard error that the key is stateful:

```text
$ keelsign keygen --alg lms-sha256-m32-h10 --out signing.pem
algorithm: lms-hss
parameter set: LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=1
key id: 5c1e...  (32 hex digits)
private key: signing.pem (PKCS#8 PEM, not encrypted)
signatures: 1024
state: signing.pem.state (next leaf 0)
journal: signing.pem.journal
```

## Stateful LMS keys

An LMS/HSS signature uses a one-time key, a leaf of the tree. Two signatures with the
same leaf let anyone forge signatures, so the key carries state: which leaves are used.
`keygen` writes it next to the key, and `sign` keeps it:

- `FILE.state`: JSON, `"format": "keelsign-lms-state"`, `"version": 1`, the key ID it
  belongs to (`key_id`), the next leaf (`next_leaf`, counted over both levels), the
  number of leaves (`leaves`) and cached tree nodes (`levels`: the nodes at heights 10
  and up of the top tree and, with two levels, of the current bottom tree, with its
  public key and the top-level signature over it). The caches are public values; they
  spare `sign` from recomputing the whole tree. It is only ever replaced whole: written
  to a temporary file `.FILE.state.keelsign-tmp-PID`, flushed to disk, renamed over the
  old file, and the directory flushed.
- `FILE.journal`: an append-only log. Its first line, `keelsign-lms-journal 1 KEYID`
  (the key ID in hex), binds it to the key; then one line `reserved LEAF UNIX-SECONDS`
  per signature (digits only), each flushed to disk before `sign` goes on. A journal
  without that header, or with another key's ID, is refused (exit 10). It is also the
  key's lock.

`sign` with an LMS/HSS key, after it has parsed the image, loaded the keys and computed
the image digest `M`, and before it computes any signature:

1. takes an exclusive lock on the journal (`flock`); if another keelsign process holds
   it, `sign` stops at once with exit code 10 ("locked by another keelsign process");
2. reads the state file and checks that it belongs to the key (its key ID), that a leaf
   is left (otherwise exit code 11, `LeafIndexExhausted`), and that it is not behind the
   journal: if the journal records a leaf at or after the state file's next leaf, the
   state file was restored from a copy, and `sign` refuses with exit code 10 ("do not
   sign, retire this key");
3. with two levels, builds the next bottom tree if the leaf is the first of a new one
   (signed by the next top-level leaf; this is deterministic, so a crash part-way
   repeats the same signature rather than making a second one);
4. writes the state file with the next leaf advanced, then appends the reservation to
   the journal;
5. signs, verifies the signed image, writes `OUT` and only then releases the lock.

A crash (power loss, `kill -9`) anywhere after step 4 wastes the reserved leaf; the
next `sign` uses the one after it, never the same one. `sign` prints the leaf it used
(`leaf: 0 of 1024 (1023 left)`) and `inspect` shows the leaf of every level
(`leaf indices`).

Rules for an LMS/HSS key:

- Keep `FILE`, `FILE.state` and `FILE.journal` together in one directory on a local
  disk, and sign only with keelsign. The lock is advisory and local: two machines (or a
  network file system that does not honour `flock`) are not kept apart.
- Never copy the key to a second machine and sign on both, and never restore it from a
  backup to sign again: either reuses leaves. A restored state file alone is caught by
  the journal (exit 10); a restored or copied directory (key, state and journal
  together) cannot be told apart from the original, so keelsign does not detect it.
- A missing state file or journal is refused (exit 10). keelsign does not rebuild them:
  if the state is lost, retire the key and enrol a new one.
- A state file of another key is refused (exit 10): the state is bound to the key ID of
  the key's public key, not to file names or times.
- Plan the next key before the leaves run out: `sign` prints how many are left, and a
  used-up key fails with exit code 11 (`LeafIndexExhausted`). Generate the new key, put
  its public key on the devices, then switch.
- `keygen` refuses to replace an existing key, state file or journal without `--force`
  (exit 3). `--force` writes a new key with fresh state; the old key's state is gone.
  Never run `keygen --force` over a key while a `sign` with it is running: the running
  `sign` can then write the old key's state over the new key's state file, and the new
  key is refused with exit code 10 (its state belongs to another key) from then on.

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
- LMS/HSS: `key id` = the first 16 bytes of SHA-256 over the 60-byte HSS public key
  (`u32 L` and the top tree's LMS public key), the key `verify --pub` trusts.
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
- The LMS/HSS state file and journal are created with mode `0600` as well.
- On other platforms (Windows) no access-control change is made; `keygen` prints a note,
  and protecting the file is up to you.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | I/O error (unreadable key, passphrase, image or `--pub` file, write failure), random-number generator failure, internal error |
| 2 | usage error: unknown command, option or `--alg` value, conflicting options, empty passphrase, passphrase file over 1 MiB, `--format der` without `--out`, `pubkey --out` naming the `--key` file |
| 3 | the output file exists and `--force` was not given |
| 4 | passphrase: wrong, missing for an encrypted key, or given for an unencrypted key |
| 5 | corrupt or unsupported key file (not PEM/DER PKCS#8, over 1 MiB, a public key, an unsupported algorithm, ML-DSA `expandedKey`/`both`, parameters present, a v2 public key that does not match, an unsupported encryption scheme or out-of-range KDF parameters; for `verify --pub`: not a PEM/DER `SubjectPublicKeyInfo`, an unknown OID, parameters present, the wrong length, or a private key) |
| 6 | the key file holds a different algorithm than `--alg` (or, for an LMS/HSS key, a different height than the `lms-sha256-m32-hNN` value) (for `sign`: `--key` is Ed25519 or `--hybrid-key` is not Ed25519) |
| 7 | `sign` / `inspect` / `verify`: the input image is rejected as malformed (see [signing.md](signing.md#exit-codes)) |
| 8 | `sign`: the input image already carries keelsign TLVs and `--replace` was not given (see [signing.md](signing.md#exit-codes)) |
| 9 | `verify`: the image is not verified under the policy (see [verify.md](verify.md#exit-codes)) |
| 10 | `sign` with an LMS/HSS key: its state is refused: the state file or journal is missing, the state file belongs to another key, is behind the journal (restored from a copy: retire the key), or is corrupt, or another keelsign process holds the key's lock (see [Stateful LMS keys](#stateful-lms-keys)) |
| 11 | `sign` with an LMS/HSS key: `LeafIndexExhausted`, every leaf of the key is used; generate a new key |

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
