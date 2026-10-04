# keelsign

**Status: pre-release.** The CLI has `keygen`, `pubkey`, `sign` (ML-DSA-44/65,
optionally hybrid with Ed25519) and `inspect`; `verify` is to come. The library API is
unstable and exists only for the CLI and its tests.

`keelsign` is the host CLI of the keelsign post-quantum firmware signing kit, for
MCUboot-format images signed with ML-DSA or LMS/HSS (optionally hybrid with Ed25519).

```sh
keelsign keygen --alg ml-dsa-44 --out signing.pem       # also ml-dsa-65, ed25519
keelsign pubkey --key signing.pem --out signing.pub.pem
keelsign sign --key signing.pem app.signed.bin app.keelsign.bin   # [--hybrid-key ed25519.pem]
keelsign inspect --json app.keelsign.bin
```

Keys are PKCS#8 (optionally passphrase-encrypted) and SubjectPublicKeyInfo files with
the standard OIDs. See
[docs/keys.md](https://github.com/smhasan94/keelsign/blob/main/docs/keys.md) for the
formats, passphrases, key IDs and exit codes, and
[docs/signing.md](https://github.com/smhasan94/keelsign/blob/main/docs/signing.md) for
signing, the TLVs added, `inspect` and its JSON schema.

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
