# keelsign_hello

A Zephyr application for `nrf52840dk/nrf52840` that MCUboot boots only after keelsign
has verified its post-quantum (LMS/HSS) signature, in MCUboot's image-check hook, and
MCUboot has verified its own ECDSA P-256 signature (SHA-62).

- `sysbuild.conf`: MCUboot with ECDSA P-256 (imgtool) and `SB_CONFIG_KEELSIGN=y`
  (post-quantum-only policy) signing with `keelsign-dev.pem`.
- `sysbuild/mcuboot.conf`: a 16 KB main stack and INF logging for MCUboot.
- `boards/nrf52840dk_nrf52840.overlay`: a 64 KB boot partition and two 464 KB slots;
  `sysbuild/mcuboot.overlay` includes it for the MCUboot image.
- `src/main.c`: prints `hello from keelsign_hello on nrf52840dk/nrf52840, linked at
  0x10000` (the start of slot 0, where the image header is), then a tick a second.

`keelsign-dev.pem` (with its `.state` and `.journal`) is a stateful LMS/HSS key you make
yourself, in this directory, and never commit:

```sh
keelsign keygen --alg lms-sha256-m32-h10 --out samples/keelsign_hello/keelsign-dev.pem
```

Setup, build, flashing and the on-board checks are in
[docs/mcuboot.md](../../docs/mcuboot.md).
