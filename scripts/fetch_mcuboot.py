#!/usr/bin/env python3
"""A pinned MCUboot checkout for the host hook harness (SHA-62, mcuboot/hooktest).

Usage:
    fetch_mcuboot.py [--rev v2.4.0|v2.5.0-rc1] [--dest DIR]

Prints the absolute path of an MCUboot source tree at the pinned commit:

  * v2.4.0 (default): 6d3b3d2c38ab20c242e5b9abb04d050086383eb2, the MCUboot that Zephyr
    v4.4.2 pins (west.yml) and the hook glue is built against.
  * v2.5.0-rc1: bcb0fe5a66c6b795817fa3280ce991bfc128af72, compiled against only to show
    the glue builds with the next release's headers (same boot_image_check_hook).

With KEELSIGN_MCUBOOT_DIR set (for example the west workspace's bootloader/mcuboot),
v2.4.0 uses that tree instead of cloning, after checking that its HEAD is the pinned
commit; offline runs need nothing else. Otherwise the tree is cloned once
(`git clone --filter=blob:none`) into DIR (default target/mcuboot-<short sha> under the
repository root), checked out at the pinned commit and its HEAD asserted; a later run
reuses it. Needs git and, for a fresh clone, network access to github.com.

Standard library only.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

URL = "https://github.com/mcu-tools/mcuboot"
PINS = {
    "v2.4.0": "6d3b3d2c38ab20c242e5b9abb04d050086383eb2",
    "v2.5.0-rc1": "bcb0fe5a66c6b795817fa3280ce991bfc128af72",
}
ROOT = Path(__file__).resolve().parent.parent


def git(*args, cwd=None):
    out = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def head_of(tree):
    try:
        return git("rev-parse", "HEAD", cwd=tree)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rev", choices=sorted(PINS), default="v2.4.0")
    ap.add_argument("--dest", type=Path, help="clone directory (default target/mcuboot-<sha>)")
    args = ap.parse_args()
    sha = PINS[args.rev]

    override = os.environ.get("KEELSIGN_MCUBOOT_DIR")
    if override and args.rev == "v2.4.0":
        tree = Path(override).resolve()
        head = head_of(tree)
        if head != sha:
            sys.exit(f"fetch_mcuboot: KEELSIGN_MCUBOOT_DIR={tree} is at {head}, expected {sha} ({args.rev})")
        print(tree)
        return

    dest = (args.dest or ROOT / "target" / f"mcuboot-{sha[:7]}").resolve()
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", URL, str(dest)],
            check=True,
        )
    if head_of(dest) != sha:
        subprocess.run(["git", "-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "--quiet", sha], check=True)
    head = head_of(dest)
    if head != sha:
        sys.exit(f"fetch_mcuboot: {dest} is at {head}, expected {sha} ({args.rev})")
    print(dest)


if __name__ == "__main__":
    main()
