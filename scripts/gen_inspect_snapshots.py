#!/usr/bin/env python3
"""Regenerate the `keelsign inspect` snapshots in keelsign/tests/snapshots/inspect/.

For each image in IMAGES (under tests/fixtures/images/), it writes
  * <image>.txt:  the output of `keelsign inspect IMAGE`
  * <image>.json: the output of `keelsign inspect --json IMAGE`
The keelsign tests (keelsign/tests/inspect.rs) compare the binary's output with these
files byte for byte. The output depends only on the image bytes (no path, time or
terminal size), so the snapshots are reproducible.

Usage:
  python3 scripts/gen_inspect_snapshots.py                  # write the snapshots
  python3 scripts/gen_inspect_snapshots.py --check          # regenerate and diff
  python3 scripts/gen_inspect_snapshots.py --keelsign PATH  # use a built binary

Without --keelsign the binary is run with `cargo run -q -p keelsign --locked --`. Pass
--keelsign when this script itself runs under cargo (scripts/make-fixtures.sh inside a
test), so cargo is not nested. Offline; standard library only. Never edit the snapshots
by hand; rerun this script (CLAUDE.md).
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGES = REPO_ROOT / "tests" / "fixtures" / "images"
SNAPSHOTS = REPO_ROOT / "keelsign" / "tests" / "snapshots" / "inspect"

# imgtool Ed25519 with protected TLVs; RSA-2048; a padded image (trailing bytes); hybrid
# Ed25519 + LMS with protected TLVs; ML-DSA-65 with protected TLVs; two-level HSS; and
# an image with two PQ signature TLVs.
IMAGES_TO_SNAPSHOT = [
    "mcuboot-ed25519.bin",
    "mcuboot-rsa2048.bin",
    "mcuboot-ed25519-padded.bin",
    "keelsign-hybrid-protected-tlvs.bin",
    "keelsign-mldsa65-protected-tlvs.bin",
    "keelsign-hss2-m32-h5h5.bin",
    "keelsign-dual-pq-invalid.bin",
]


def keelsign_command(binary):
    if binary:
        return [str(Path(binary).resolve())]
    return ["cargo", "run", "-q", "-p", "keelsign", "--locked", "--"]


def inspect(command, image, json_output):
    args = command + ["inspect"] + (["--json"] if json_output else []) + [str(IMAGES / image)]
    result = subprocess.run(args, cwd=REPO_ROOT, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"{' '.join(args)} failed with {result.returncode}:\n{result.stderr.decode(errors='replace')}")
    return result.stdout


def generate(out_dir, command):
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*"):
        if stale.suffix in (".txt", ".json"):
            stale.unlink()
    for image in IMAGES_TO_SNAPSHOT:
        stem = image.removesuffix(".bin")
        (out_dir / f"{stem}.txt").write_bytes(inspect(command, image, False))
        (out_dir / f"{stem}.json").write_bytes(inspect(command, image, True))


def snapshot_files(directory):
    return {p.name: p.read_bytes() for p in directory.glob("*") if p.suffix in (".txt", ".json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="regenerate into a temp dir and diff")
    parser.add_argument("--keelsign", metavar="PATH", help="the keelsign binary (default: cargo run)")
    args = parser.parse_args()
    command = keelsign_command(args.keelsign)
    if not args.check:
        generate(SNAPSHOTS, command)
        print(f"wrote {2 * len(IMAGES_TO_SNAPSHOT)} snapshots to {SNAPSHOTS.relative_to(REPO_ROOT)}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        generate(fresh, command)
        want, have = snapshot_files(fresh), snapshot_files(SNAPSHOTS) if SNAPSHOTS.exists() else {}
        problems = [f"missing snapshot {n}" for n in sorted(want.keys() - have.keys())]
        problems += [f"stale snapshot {n}" for n in sorted(have.keys() - want.keys())]
        problems += [f"snapshot {n} differs" for n in sorted(want.keys() & have.keys()) if want[n] != have[n]]
        if problems:
            print("\n".join(problems), file=sys.stderr)
            sys.exit("inspect snapshots do not match a fresh regeneration; run python3 scripts/gen_inspect_snapshots.py")
        print(f"{len(want)} snapshots: inspect snapshots match a fresh regeneration")


if __name__ == "__main__":
    main()
