#!/usr/bin/env python3
"""Static stack frame sizes from the `.stack_sizes` section of a 32-bit ELF.

PROVISIONAL, NOT THE DECISION. This reads the per-function frame sizes that nightly
rustc emits with `-Z emit-stack-sizes`. They are each function's own frame only (no call
graph), so the figure for `mldsa_kat::verify_case` is the frame reserved by verify with
everything LLVM inlined into it, not the true peak. The go/no-go decision uses the stack
watermark measured on the boards (docs/benchmarks.md).

Build the ELF with nightly (from benches/<board>-mldsa, see docs/benchmarks.md):

  cargo +nightly rustc --release --locked --bin size_mldsa44 --target-dir target/nightly \
      -- -Z emit-stack-sizes

Usage:
  python3 scripts/stack_frames.py ELF [--top N] [--match SUBSTRING]

Prints the N largest frames and every function whose demangled name contains SUBSTRING
(default `verify_case`). Standard library only.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

STT_FUNC = 2


def sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("expected a 32-bit little-endian ELF")
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = headers[shstrndx][4]
    named = {}
    for h in headers:
        start = strtab + h[0]
        named[data[start : data.index(b"\0", start)].decode()] = h
    return headers, named


def function_symbols(data, headers, named):
    """Returns {address without the Thumb bit: mangled name} for STT_FUNC symbols."""
    symtab = named.get(".symtab")
    if symtab is None:
        raise ValueError("no .symtab (was the ELF stripped?)")
    strtab = headers[symtab[6]][4]
    names = {}
    for k in range(symtab[5] // 16):
        st_name, value, _size, info, _other, _shndx = struct.unpack_from("<IIIBBH", data, symtab[4] + k * 16)
        if info & 0xF == STT_FUNC:
            start = strtab + st_name
            names.setdefault(value & ~1, data[start : data.index(b"\0", start)].decode())
    return names


def stack_sizes(data, named):
    """Yields (address, frame bytes) from .stack_sizes: u32 address, ULEB128 size."""
    sec = named.get(".stack_sizes")
    if sec is None:
        raise ValueError("no .stack_sizes section: build with nightly `-Z emit-stack-sizes`")
    pos, end = sec[4], sec[4] + sec[5]
    while pos < end:
        (addr,) = struct.unpack_from("<I", data, pos)
        pos += 4
        size, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            size |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                break
        yield addr & ~1, size


LEGACY_ESCAPES = {"$LT$": "<", "$GT$": ">", "$u20$": " ", "$RF$": "&", "$C$": ",", "$u7b$": "{", "$u7d$": "}", "$BP$": "*", "..": "::"}


BASIC_TYPES = {
    "a": "i8", "b": "bool", "c": "char", "d": "f64", "e": "str", "f": "f32", "h": "u8",
    "i": "isize", "j": "usize", "l": "i32", "m": "u32", "n": "i128", "o": "u128",
    "s": "i16", "t": "u16", "u": "()", "v": "...", "x": "i64", "y": "u64", "z": "!", "p": "_",
}


class V0:
    """Minimal demangler for Rust v0 symbols (`_R…`), enough to name functions."""

    def __init__(self, sym):
        self.s = sym
        self.pos = 2

    def peek(self):
        return self.s[self.pos] if self.pos < len(self.s) else ""

    def eat(self, c):
        if self.peek() == c:
            self.pos += 1
            return True
        return False

    def base62(self):
        if self.eat("_"):
            return 0
        n = 0
        while (c := self.peek()) != "_":
            if not c:
                raise ValueError("truncated base-62 number")
            n = n * 62 + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".index(c)
            self.pos += 1
        self.pos += 1
        return n + 1

    def backref(self, parse):
        start = self.pos - 1
        target = self.base62() + 2
        if target >= start:
            raise ValueError("forward backref")
        saved, self.pos = self.pos, target
        out = parse()
        self.pos = saved
        return out

    def ident(self):
        if self.eat("s"):
            self.base62()
        punycode = self.eat("u")
        m = re.match(r"\d+", self.s[self.pos :])
        if not m:
            raise ValueError("expected identifier")
        self.pos += len(m.group())
        length = int(m.group())
        self.eat("_")
        text = self.s[self.pos : self.pos + length]
        self.pos += length
        return f"{text}(punycode)" if punycode else text

    def path(self):
        c = self.peek()
        self.pos += 1
        if c == "C":
            return self.ident()
        if c == "M":
            self.impl_path()
            return f"<{self.type_()}>"
        if c == "X":
            self.impl_path()
            ty = self.type_()
            return f"<{ty} as {self.path()}>"
        if c == "Y":
            ty = self.type_()
            return f"<{ty} as {self.path()}>"
        if c == "N":
            ns = self.peek()
            self.pos += 1
            parent = self.path()
            name = self.ident()
            if ns == "C":
                return f"{parent}::{{closure}}"
            if ns == "S":
                return f"{parent}::{{shim}}"
            return f"{parent}::{name}" if name else parent
        if c == "I":
            base = self.path()
            args = []
            while not self.eat("E"):
                args.append(self.generic_arg())
            return f"{base}<{', '.join(args)}>"
        if c == "B":
            return self.backref(self.path)
        raise ValueError(f"unknown path tag {c!r}")

    def impl_path(self):
        if self.eat("s"):
            self.base62()
        return self.path()

    def generic_arg(self):
        if self.eat("L"):
            self.base62()
            return "'_"
        if self.eat("K"):
            return self.const()
        return self.type_()

    def const(self):
        if self.eat("B"):
            return self.backref(self.const)
        if self.eat("p"):
            return "_"
        ty = self.type_()
        negative = self.eat("n")
        m = re.match(r"[0-9a-f]*_", self.s[self.pos :])
        if not m:
            raise ValueError("bad const")
        self.pos += len(m.group())
        digits = m.group()[:-1] or "0"
        value = int(digits, 16)
        if ty == "bool":
            return "true" if value else "false"
        return f"{'-' if negative else ''}{value}"

    def binder(self):
        if self.eat("G"):
            self.base62()

    def type_(self):
        c = self.peek()
        if c in BASIC_TYPES:
            self.pos += 1
            return BASIC_TYPES[c]
        self.pos += 1
        if c == "R" or c == "Q":
            if self.eat("L"):
                self.base62()
            return ("&" if c == "R" else "&mut ") + self.type_()
        if c == "P" or c == "O":
            return ("*const " if c == "P" else "*mut ") + self.type_()
        if c == "A":
            ty = self.type_()
            return f"[{ty}; {self.const()}]"
        if c == "S":
            return f"[{self.type_()}]"
        if c == "T":
            items = []
            while not self.eat("E"):
                items.append(self.type_())
            return f"({', '.join(items)})"
        if c == "F":
            self.binder()
            self.eat("U")
            if self.eat("K"):
                if not self.eat("C"):
                    self.ident()
            args = []
            while not self.eat("E"):
                args.append(self.type_())
            return f"fn({', '.join(args)}) -> {self.type_()}"
        if c == "D":
            self.binder()
            traits = []
            while not self.eat("E"):
                traits.append(self.path())
                while self.eat("p"):
                    self.ident()
                    self.type_()
            if self.eat("L"):
                self.base62()
            return "dyn " + " + ".join(traits)
        if c == "B":
            return self.backref(self.type_)
        self.pos -= 1
        return self.path()

    def demangle(self):
        m = re.match(r"\d+", self.s[self.pos :])
        if m:
            self.pos += len(m.group())
        return self.path()


def demangle(name):
    """Demangles Rust v0 (`_R…`) and legacy (`_ZN…E`) symbols; returns others unchanged."""
    if name.startswith("_R"):
        try:
            return V0(name).demangle()
        except (ValueError, IndexError, RecursionError):
            return name
    if not name.startswith("_ZN"):
        return name
    parts, pos = [], 3
    while pos < len(name) and name[pos] != "E":
        m = re.match(r"\d+", name[pos:])
        if not m:
            return name
        length = int(m.group())
        pos += len(m.group())
        parts.append(name[pos : pos + length])
        pos += length
    if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
        parts.pop()
    out = "::".join(parts)
    for escape, text in LEGACY_ESCAPES.items():
        out = out.replace(escape, text)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("elf")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--match", default="verify_case")
    args = parser.parse_args()

    try:
        data = Path(args.elf).read_bytes()
        headers, named = sections(data)
        names = function_symbols(data, headers, named)
        frames = sorted(
            ((size, demangle(names.get(addr, f"0x{addr:08x}"))) for addr, size in stack_sizes(data, named)),
            reverse=True,
        )
    except (OSError, ValueError, struct.error, IndexError) as e:
        sys.exit(f"stack_frames: {e}")

    print(f"# {Path(args.elf).name}: static frames (provisional, own frame only)")
    for size, name in frames[: args.top]:
        print(f"{size:>8}  {name}")
    matches = [(size, name) for size, name in frames if args.match in name]
    print(f"# functions matching {args.match!r}")
    for size, name in matches:
        print(f"{size:>8}  {name}")
    if not matches:
        sys.exit(f"stack_frames: no function matching {args.match!r}")


if __name__ == "__main__":
    main()
