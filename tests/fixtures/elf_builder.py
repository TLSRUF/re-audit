"""Hand-builds minimal, valid ELF64 PIE binaries with a PT_GNU_RELRO segment
and a configurable DT_FLAGS_1 / DT_BIND_NOW dynamic entry.

Exists so the RELRO-classification regression test doesn't depend on a C
toolchain being available (this project's CI and dev machines are Windows).
Produces the exact minimal structure `lief.parse()` needs: ELF header + 3
program headers (LOAD, DYNAMIC, GNU_RELRO) + a dynamic entry table. No
section headers -- re-audit's binary analyzer only reads segments/dynamic
entries for this check, and LIEF parses section-header-less ELFs fine.
"""
from __future__ import annotations

import struct

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_RELRO = 0x6474E552
DT_NULL = 0
DT_FLAGS_1 = 0x6FFFFFFB
DT_BIND_NOW = 24
DF_1_NOW = 0x00000001
DF_1_PIE = 0x08000000


def build_elf(*, bind_now_tag: bool = False, flags_1_now_bit: bool = False) -> bytes:
    """Build a minimal ET_DYN (PIE) ELF64 with a GNU_RELRO segment.

    `bind_now_tag`: include the legacy boolean DT_BIND_NOW tag.
    `flags_1_now_bit`: set DF_1_NOW in the DT_FLAGS_1 entry's value.
    Neither set -> "partial RELRO" (GNU_RELRO segment present, no eager
    binding). Either set -> "full RELRO".
    """
    ehdr_size = 64
    phdr_size = 56
    n_phdr = 3
    phoff = ehdr_size
    dyn_off = phoff + n_phdr * phdr_size

    entries = []
    if bind_now_tag:
        entries.append((DT_BIND_NOW, 0))
    flags1_val = DF_1_PIE | (DF_1_NOW if flags_1_now_bit else 0)
    entries.append((DT_FLAGS_1, flags1_val))
    entries.append((DT_NULL, 0))
    dyn_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in entries)
    dyn_size = len(dyn_bytes)

    total_size = dyn_off + dyn_size
    vaddr_base = 0x1000  # file offset == vaddr for this minimal layout

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        3,          # e_type = ET_DYN
        62,         # e_machine = EM_X86_64
        1,          # e_version
        0,          # e_entry
        phoff,
        0,          # e_shoff
        0,          # e_flags
        ehdr_size,
        phdr_size,
        n_phdr,
        0, 0, 0,    # e_shentsize, e_shnum, e_shstrndx
    )

    def phdr(p_type, p_flags, offset, size):
        return struct.pack(
            "<IIQQQQQQ",
            p_type, p_flags, offset, vaddr_base + offset, vaddr_base + offset,
            size, size, 0x1000,
        )

    phdrs = (
        phdr(PT_LOAD, 6, 0, total_size)
        + phdr(PT_DYNAMIC, 6, dyn_off, dyn_size)
        + phdr(PT_GNU_RELRO, 4, dyn_off, dyn_size)
    )

    return ehdr + phdrs + dyn_bytes


def build_elf_no_relro() -> bytes:
    """A dynamic ELF with no GNU_RELRO segment at all -> relro should be "none"."""
    ehdr_size = 64
    phdr_size = 56
    n_phdr = 2  # LOAD, DYNAMIC only
    phoff = ehdr_size
    dyn_off = phoff + n_phdr * phdr_size

    dyn_bytes = struct.pack("<qQ", DT_NULL, 0)
    dyn_size = len(dyn_bytes)
    total_size = dyn_off + dyn_size
    vaddr_base = 0x1000

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, 3, 62, 1, 0, phoff, 0, 0, ehdr_size, phdr_size, n_phdr, 0, 0, 0,
    )

    def phdr(p_type, p_flags, offset, size):
        return struct.pack(
            "<IIQQQQQQ",
            p_type, p_flags, offset, vaddr_base + offset, vaddr_base + offset,
            size, size, 0x1000,
        )

    phdrs = phdr(PT_LOAD, 6, 0, total_size) + phdr(PT_DYNAMIC, 6, dyn_off, dyn_size)
    return ehdr + phdrs + dyn_bytes
