#!/usr/bin/env python3
"""Flash and static RAM of MCUboot without and with keelsign (SHA-62, docs/benchmarks.md).

Usage:
    mcuboot_sizes.py STOCK_ELF KEELSIGN_ELF

Both are MCUboot `zephyr.elf` files of the keelsign_hello sample
(`build-stock/mcuboot/zephyr/zephyr.elf`, `build/mcuboot/zephyr/zephyr.elf`, from
`scripts/zephyr_sample_ci.sh stock-build build`). Prints the markdown table of
docs/benchmarks.md#mcuboot-with-keelsign-sha-62:

    | MCUboot image | Flash | Static RAM | MAIN_STACK_SIZE | Compiler |
    | stock | ... | ... | ... | ... |
    | with keelsign | ... | ... | ... | ... |
    | Δ | +... | +... | | |

Zephyr names its output sections without the usual dots (`text`, `rodata`, `datas`,
`bss`, `noinit`, ...), so the figures come from the ELF's loadable segments, exactly as
the linker's memory report ("Memory region / Used Size") counts them, alignment gaps
included:

  flash      = from the lowest to the highest flash load address with contents: code,
               read-only data and the initial values of RAM data, all programmed into
               the boot partition
  static RAM = from the start of SRAM (0x20000000) to the end of the highest RAM
               segment: data, bss and noinit, which holds the thread stacks

MAIN_STACK_SIZE is read from the image's `.config` next to the ELF, the compiler from
the ELF's `.comment` section. Standard library only, like elf_sizes.py (which sums the
dotted section names of the Rust bench ELFs).
"""

import struct
import sys
from pathlib import Path

PT_LOAD = 1
RAM_START = 0x20000000


def segments(data):
    """(vaddr, paddr, filesz, memsz) of each PT_LOAD segment of a 32-bit LE ELF."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("expected a 32-bit little-endian ELF")
    (phoff,) = struct.unpack_from("<I", data, 0x1C)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    out = []
    for i in range(phnum):
        typ, _off, vaddr, paddr, filesz, memsz = struct.unpack_from("<IIIIII", data, phoff + i * phentsize)
        if typ == PT_LOAD:
            out.append((vaddr, paddr, filesz, memsz))
    return out


def comment(data):
    """The first string of the `.comment` section (the compiler), or ""."""
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    raw = [struct.unpack_from("<IIIIII", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = raw[shstrndx][4]
    for name, _typ, _flags, _addr, offset, size in raw:
        if data[strtab + name : data.index(b"\0", strtab + name)] == b".comment":
            return data[offset : offset + size].split(b"\0")[0].decode()
    return ""


def measure(elf):
    data = Path(elf).read_bytes()
    loads = segments(data)
    in_flash = [(p, p + f) for _v, p, f, _m in loads if f and p < RAM_START]
    in_ram = [v + m for v, _p, _f, m in loads if v >= RAM_START]
    if not in_flash or not in_ram:
        raise ValueError(f"{elf}: no flash or no RAM segment")
    flash = max(e for _s, e in in_flash) - min(s for s, _e in in_flash)
    ram = max(in_ram) - RAM_START
    stack = ""
    config = Path(elf).parent / ".config"
    if config.is_file():
        for line in config.read_text().splitlines():
            if line.startswith("CONFIG_MAIN_STACK_SIZE="):
                stack = line.split("=", 1)[1]
    return flash, ram, stack, comment(data)


def grouped(n):
    return f"{n:,} B"


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: mcuboot_sizes.py STOCK_ELF KEELSIGN_ELF")
    try:
        stock = measure(sys.argv[1])
        keelsign = measure(sys.argv[2])
    except (OSError, ValueError, struct.error) as e:
        sys.exit(f"mcuboot_sizes: {e}")
    print("| MCUboot image | Flash | Static RAM | MAIN_STACK_SIZE | Compiler |")
    print("|---|---|---|---|---|")
    for label, (flash, ram, stack, comment) in (("stock", stock), ("with keelsign", keelsign)):
        print(f"| {label} | {grouped(flash)} | {grouped(ram)} | {stack} | {comment} |")
    print(f"| Δ | {keelsign[0] - stock[0]:+,} B | {keelsign[1] - stock[1]:+,} B | | |")


if __name__ == "__main__":
    main()
