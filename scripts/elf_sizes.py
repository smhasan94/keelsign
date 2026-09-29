#!/usr/bin/env python3
"""Section sizes of 32-bit little-endian ELF files (Cortex-M firmware), as markdown rows.

Pure Python (standard library only), so no llvm-tools / cargo-binutils install is needed.

  flash = .text + .rodata + .data  (the bytes programmed into flash for the code under
                                    test; the vector table and RP2350 boot blocks are the
                                    same in every bin and are left out)
  ram   = .data + .bss + .uninit   (static RAM; the stack is measured separately)

Usage:
  python3 scripts/elf_sizes.py ELF [ELF ...]
  python3 scripts/elf_sizes.py --baseline BASE_ELF ELF [ELF ...]   # adds delta columns
  python3 scripts/elf_sizes.py --label nrf52840/release --baseline BASE ELF ...

Prints a markdown table with one row per ELF.
"""

import argparse
import struct
import sys
from pathlib import Path

FLASH_SECTIONS = (".text", ".rodata", ".data")
RAM_SECTIONS = (".data", ".bss", ".uninit")
COLUMNS = (".text", ".rodata", ".data", ".bss")


def section_sizes(path):
    """Returns {section name: size} for a 32-bit little-endian ELF file."""
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{path}: not an ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ValueError(f"{path}: expected a 32-bit little-endian ELF")
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = []
    for i in range(shnum):
        name, _type, _flags, _addr, _offset, size = struct.unpack_from(
            "<IIIIII", data, shoff + i * shentsize
        )
        headers.append((name, size, _offset))
    strtab_offset = headers[shstrndx][2]
    sizes = {}
    for name_offset, size, _ in headers:
        start = strtab_offset + name_offset
        end = data.index(b"\0", start)
        sizes[data[start:end].decode()] = size
    return sizes


def totals(sizes):
    flash = sum(sizes.get(s, 0) for s in FLASH_SECTIONS)
    ram = sum(sizes.get(s, 0) for s in RAM_SECTIONS)
    return flash, ram


def row(label, path, sizes, base=None):
    flash, ram = totals(sizes)
    cells = [label, Path(path).name] + [str(sizes.get(s, 0)) for s in COLUMNS] + [str(flash), str(ram)]
    if base is not None:
        base_flash, base_ram = totals(base)
        cells += [f"{flash - base_flash:+d}", f"{ram - base_ram:+d}"]
    return "| " + " | ".join(cells) + " |"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("elves", nargs="+", metavar="ELF")
    parser.add_argument("--baseline", metavar="ELF", help="ELF to subtract for the delta columns")
    parser.add_argument("--label", default="", help="first-column label, e.g. nrf52840/release")
    args = parser.parse_args()

    base = section_sizes(args.baseline) if args.baseline else None
    header = ["label", "elf"] + list(COLUMNS) + ["flash", "static RAM"]
    if base is not None:
        header += ["Δ flash", "Δ static RAM"]
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for elf in args.elves:
        try:
            sizes = section_sizes(elf)
        except (OSError, ValueError, struct.error) as e:
            sys.exit(f"elf_sizes: {e}")
        print(row(args.label, elf, sizes, base))


if __name__ == "__main__":
    main()
