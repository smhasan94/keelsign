#!/usr/bin/env python3
"""Flash size and symbol check of libkeelsign.a (keelsign-ffi, SHA-60).

Usage:
    staticlib_sizes.py [--features F] [--symbols] [--strings] [--check] ARCHIVE...

For each GNU-format static library built for a bare-metal ELF target (from
`cargo build -p keelsign-ffi --profile ffi --target <triple>`), finds the one
`keelsign-*` member (with `lto = "fat"` all Rust code, core and the dependencies
included, is in it; the other members are compiler_builtins) and prints a markdown row
for docs/benchmarks.md:

    | <triple> | <features> | <.text> B | <.rodata> B | <.text + .rodata> B |

`.text` and `.rodata` are the sums of the member's `.text*` and `.rodata*` sections;
the member has no `.data` or `.bss`. The triple is read from the path
(`target/<triple>/ffi/libkeelsign.a`); `--features` labels the row (`(none)` without).

--symbols prints the member's exported, undefined and panic-related symbols.
--strings prints the printable runs in its `.rodata*` sections.
--check fails (exit 1) unless, for every archive:
  * the exported functions are exactly keelsign_verify, keelsign_verify_cb and
    keelsign_digest;
  * no symbol is formatting code (core::fmt, Formatter, Display, Debug, LowerHex, ...);
  * every panic-related symbol is one of the libcore trap funnels PANIC_ALLOWLIST
    allows for the `--features` state given, and at most 32 bytes;
  * `.rodata*` holds no printable run of 8 or more characters other than
    `keelsign-mcuboot-image-v1`, and none mentioning `.rs`, `panicked` or `attempt to`;
  * the member has no `.data*` / `.bss*`.

Standard library only.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

# The libcore panic entry points (called from sha2, ed25519-dalek, ml-dsa) that survive on stable with `panic = "abort"`
# and a panic handler that never formats (docs/ffi.md#nm-check): name fragment of the
# (legacy or v0) mangled symbol -> description.
# Feature conditions of the allowlist, as tools/repo-checks/tests/ffi.rs names them too.
ALWAYS = "always"
ED25519_OR_ML_DSA = "ed25519 or ml-dsa"
ML_DSA = "ml-dsa"
# fragment -> (description, the feature states it is allowed in). Measured per state
# (docs/ffi.md#nm-check); the default LMS-only build gets only the ALWAYS three.
PANIC_ALLOWLIST = {
    "9panicking9panic_fmt": ("core::panicking::panic_fmt", ALWAYS),
    "panic_const_div_by_zero": ("core::panicking::panic_const::panic_const_div_by_zero", ALWAYS),
    "len_mismatch_fail": ("core::slice::copy_from_slice::len_mismatch_fail", ALWAYS),
    "panic_bounds_check": ("core::panicking::panic_bounds_check", ED25519_OR_ML_DSA),
    "16slice_index_fail": ("core::slice::index::slice_index_fail", ED25519_OR_ML_DSA),
    "9panicking5panic": ("core::panicking::panic", ML_DSA),
    "6option13expect_failed": ("core::option::expect_failed", ML_DSA),
    "6result13unwrap_failed": ("core::result::unwrap_failed", ML_DSA),
}
# A trap funnel is a branch into the panic handler: a few instructions.
PANIC_FUNNEL_MAX = 32
# A symbol naming any of these is a panic path and must be allowlisted.
PANIC_MARKERS = ("panic", "_fail", "unwrap", "assert", "unreachable")
FORMATTING_MARKERS = (
    "4core3fmt",
    "core..fmt",
    "Formatter",
    "fmt5write",
    "7Display",
    "5Debug",
    "8LowerHex",
    "8UpperHex",
    "9Arguments",
)
EXPORTS = ["keelsign_digest", "keelsign_verify", "keelsign_verify_cb"]
ALLOWED_STRINGS = ("keelsign-mcuboot-image-v1",)
FORBIDDEN_IN_STRINGS = (".rs", "panicked", "attempt to")
MIN_STRING = 8


def ar_members(data):
    """(name, body) of each member of a GNU (System V) ar archive."""
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    off = 8
    longnames = b""
    while off + 60 <= len(data):
        hdr = data[off : off + 60]
        name = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip())
        body = data[off + 60 : off + 60 + size]
        off += 60 + size + (size & 1)
        if name == "//":
            longnames = body
        elif name in ("/", "/SYM64/"):
            continue
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = longnames.index(b"/\n", start)
            yield longnames[start:end].decode(), body
        elif name.startswith("#1/"):
            raise ValueError("BSD ar archive (host build?); pass a bare-metal ELF build")
        else:
            yield name.rstrip("/"), body


class Elf:
    """The sections and symbols of a little-endian ELF relocatable object."""

    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        if data[5] != 1:
            raise ValueError("big-endian ELF")
        self.data = data
        self.is64 = data[4] == 2
        if self.is64:
            (shoff,) = struct.unpack_from("<Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
            fmt = "<IIQQQQIIQQ"
        else:
            (shoff,) = struct.unpack_from("<I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
            fmt = "<IIIIIIIIII"
        raw = [struct.unpack_from(fmt, data, shoff + i * shentsize) for i in range(shnum)]
        names_off = raw[shstrndx][4]
        self.sections = []
        for name_off, typ, _flags, _addr, offset, size, link, _info, _align, entsize in raw:
            self.sections.append(
                {
                    "name": self._cstr(names_off + name_off),
                    "type": typ,
                    "offset": offset,
                    "size": size,
                    "link": link,
                    "entsize": entsize,
                }
            )

    def _cstr(self, at):
        end = self.data.index(b"\0", at)
        return self.data[at:end].decode("utf-8", "replace")

    def symbols(self):
        """(name, size, bind, type, defined) of every symbol in .symtab."""
        out = []
        for sec in self.sections:
            if sec["type"] != 2:  # SHT_SYMTAB
                continue
            strtab = self.sections[sec["link"]]["offset"]
            entsize = sec["entsize"] or (24 if self.is64 else 16)
            for i in range(1, sec["size"] // entsize):
                at = sec["offset"] + i * entsize
                if self.is64:
                    name, info, _other, shndx, _value, size = struct.unpack_from("<IBBHQQ", self.data, at)
                else:
                    name, _value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", self.data, at)
                bind, typ = info >> 4, info & 0xF
                if typ in (3, 4):  # STT_SECTION, STT_FILE
                    continue
                out.append((self._cstr(strtab + name), size, bind, typ, shndx != 0))
        return out

    def section_sum(self, prefix):
        return sum(
            s["size"] for s in self.sections if s["name"] == prefix or s["name"].startswith(prefix + ".")
        )

    def section_bytes(self, prefix):
        for s in self.sections:
            if (s["name"] == prefix or s["name"].startswith(prefix + ".")) and s["type"] != 8:
                yield s["name"], self.data[s["offset"] : s["offset"] + s["size"]]


def triple_of(path):
    parts = Path(path).resolve().parts
    if len(parts) >= 3 and parts[-2] == "ffi":
        return parts[-3]
    return "?"


def grouped(n):
    return f"{n:,}"


def keelsign_member(path):
    members = [(n, b) for n, b in ar_members(Path(path).read_bytes()) if n.startswith("keelsign-")]
    if len(members) != 1:
        raise ValueError(f"{path}: expected one keelsign-* member, found {[n for n, _ in members]}")
    return members[0][0], Elf(members[0][1])


def panic_symbol(name):
    return any(m in name for m in PANIC_MARKERS)


def condition_holds(condition, features):
    """Whether an allowlist condition holds for a `--features` value."""
    on = {f.strip() for f in features.split(",") if f.strip()}
    if condition == ALWAYS:
        return True
    if condition == ED25519_OR_ML_DSA:
        return bool(on & {"ed25519", "ml-dsa"})
    if condition == ML_DSA:
        return "ml-dsa" in on
    raise ValueError(f"unknown allowlist condition {condition!r}")


def funnel_of(name):
    """(description, condition) of the allowlisted funnel `name` is, or None."""
    for fragment, entry in PANIC_ALLOWLIST.items():
        if fragment == "9panicking5panic":
            # core::panicking::panic itself, not panic_fmt / panic_bounds_check / ...
            if re.search(r"9panicking5panic(?![A-Za-z_])", name):
                return entry
        elif fragment in name:
            return entry
    return None


def allowlisted(name, features):
    """The description of `name` if it is a funnel allowed in this feature state."""
    entry = funnel_of(name)
    if entry and condition_holds(entry[1], features):
        return entry[0]
    return None


def strings_of(elf):
    out = []
    for section, data in elf.section_bytes(".rodata"):
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_STRING, data):
            out.append((section, m.group().decode("ascii")))
    return out


def check(path, elf, show_symbols, show_strings, features=""):
    problems = []
    symbols = elf.symbols()
    exports = sorted(n for n, _s, bind, typ, d in symbols if d and bind == 1 and typ == 2)
    undefined = sorted({n for n, _s, _b, _t, d in symbols if not d})
    panics = [(n, size) for n, size, _b, _t, d in symbols if d and panic_symbol(n)]
    if exports != EXPORTS:
        problems.append(f"exported functions are {exports}, expected {EXPORTS}")
    for name, _size, _b, _t, _d in symbols:
        hit = next((m for m in FORMATTING_MARKERS if m in name), None)
        if hit:
            problems.append(f"formatting symbol {name} ({hit})")
    for name, size in panics:
        what = allowlisted(name, features)
        if what is None:
            entry = funnel_of(name)
            why = f"allowed only with {entry[1]}" if entry else "not an allowlisted trap funnel"
            problems.append(f"panic symbol {name}: {why} (features `{features}`)")
        elif size > PANIC_FUNNEL_MAX:
            problems.append(f"panic funnel {what} is {size} bytes (> {PANIC_FUNNEL_MAX})")
    for name, text in strings_of(elf):
        if any(f in text for f in FORBIDDEN_IN_STRINGS):
            problems.append(f"{name} holds a panic string {text!r}")
        elif not any(a in text for a in ALLOWED_STRINGS):
            problems.append(f"{name} holds an unexpected string {text!r}")
    for prefix in (".data", ".bss"):
        if elf.section_sum(prefix):
            problems.append(f"member has {prefix} ({elf.section_sum(prefix)} bytes)")
    if show_symbols:
        print(f"{path}:")
        print(f"  exports: {' '.join(exports)}")
        print(f"  undefined: {' '.join(undefined)}")
        for name, size in panics:
            print(f"  panic: {name} ({size} B) -> {allowlisted(name, features) or 'NOT ALLOWLISTED'}")
    if show_strings:
        for name, text in strings_of(elf):
            print(f"  string {name}: {text!r}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("archives", nargs="+", metavar="ARCHIVE")
    ap.add_argument("--features", default="", help="feature label of the row")
    ap.add_argument("--symbols", action="store_true", help="print exports, undefined and panic symbols")
    ap.add_argument("--strings", action="store_true", help="print .rodata strings")
    ap.add_argument("--check", action="store_true", help="fail on a symbol or string rule")
    args = ap.parse_args()
    failed = False
    for path in args.archives:
        try:
            _member, elf = keelsign_member(path)
        except (OSError, ValueError) as e:
            print(f"error: {path}: {e}", file=sys.stderr)
            failed = True
            continue
        text, rodata = elf.section_sum(".text"), elf.section_sum(".rodata")
        features = f"`{args.features}`" if args.features else "(none)"
        print(
            f"| `{triple_of(path)}` | {features} | {grouped(text)} B | {grouped(rodata)} B "
            f"| {grouped(text + rodata)} B |"
        )
        problems = check(path, elf, args.symbols, args.strings, args.features)
        if args.check and problems:
            failed = True
            for p in problems:
                print(f"error: {path}: {p}", file=sys.stderr)
        elif problems:
            for p in problems:
                print(f"note: {path}: {p}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
