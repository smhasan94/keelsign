# keelsign

**Status: pre-release.** The CLI has `keygen`, `pubkey`, `sign` (ML-DSA-44/65 or
stateful LMS/HSS, optionally hybrid with Ed25519), `inspect` and `verify` (ML-DSA-44/65,
HSS/LMS and Ed25519 keys, under a classical, post-quantum or hybrid policy). The library
API is unstable and exists only for the CLI and its tests.

`keelsign` is the host CLI of the keelsign post-quantum firmware signing kit, for
MCUboot-format images signed with ML-DSA or LMS/HSS (optionally hybrid with Ed25519).

```sh
keelsign keygen --alg ml-dsa-44 --out signing.pem       # also ml-dsa-65, ed25519, lms-sha256-m32-h10|h15|h20
keelsign pubkey --key signing.pem --out signing.pub.pem
keelsign sign --key signing.pem app.signed.bin app.keelsign.bin   # [--hybrid-key ed25519.pem]
keelsign inspect --json app.keelsign.bin
keelsign verify --pub signing.pub.pem app.keelsign.bin   # [--pub ed25519.pub.pem] [--policy hybrid]
```

Keys are PKCS#8 (optionally passphrase-encrypted) and SubjectPublicKeyInfo files with
the standard OIDs. LMS/HSS keys are stateful: `keygen` also writes `FILE.state` and
`FILE.journal`, and `sign` records every leaf there before it signs; never copy such a
key or restore it from a backup (docs/keys.md, "Stateful LMS keys"). See
[docs/keys.md](https://github.com/smhasan94/keelsign/blob/main/docs/keys.md) for the
formats, passphrases, key IDs and exit codes, and
[docs/signing.md](https://github.com/smhasan94/keelsign/blob/main/docs/signing.md) for
signing, the TLVs added, `inspect` and its JSON schema, and
[docs/verify.md](https://github.com/smhasan94/keelsign/blob/main/docs/verify.md) for
`verify`, its policies and the exit codes.

Repository: <https://github.com/smhasan94/keelsign>

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
