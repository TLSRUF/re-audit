"""ELF / PE / Mach-O binary security posture analysis via LIEF.

Checks compile-time/link-time exploit mitigations (NX, PIE/ASLR, RELRO,
stack canary, CFG, SafeSEH, Authenticode signature) and flags imported
functions that are historically associated with memory-corruption bugs.
This is a static, read-only inspection -- it never executes the target.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import lief

RISKY_IMPORTS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "system", "popen", "exec", "execve", "execl", "execvp",
    "memcpy", "alloca", "strncpy",  # flagged only as "review usage", not inherently unsafe
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "LoadLibraryA", "LoadLibraryW", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
}


@dataclass
class MitigationReport:
    format: str
    nx: bool | None = None
    pie_or_aslr: bool | None = None
    relro: str | None = None  # "full" | "partial" | "none" | None (not ELF)
    stack_canary: bool | None = None
    stripped: bool | None = None
    signed: bool | None = None
    cfg: bool | None = None  # Control Flow Guard (PE)
    safe_seh: bool | None = None  # PE
    notes: list[str] = field(default_factory=list)


@dataclass
class BinaryReport:
    path: str
    format: str
    arch: str | None
    mitigations: MitigationReport
    risky_imports: list[str]
    imports: list[str]
    exports: list[str]
    sections: list[str]


def _analyze_elf(binary: lief.ELF.Binary) -> MitigationReport:
    report = MitigationReport(format="ELF")

    report.nx = binary.has_nx if hasattr(binary, "has_nx") else None

    # PIE: ET_DYN with no interpreter-less static exec. LIEF exposes is_pie.
    try:
        report.pie_or_aslr = bool(binary.is_pie)
    except Exception:
        report.pie_or_aslr = None

    try:
        has_relro_segment = any(
            seg.type == lief.ELF.Segment.TYPE.GNU_RELRO for seg in binary.segments
        )
        # Full RELRO requires the GNU_RELRO segment *and* eager symbol
        # binding (BIND_NOW). The presence of a DT_FLAGS/DT_FLAGS_1 entry
        # does not by itself mean BIND_NOW -- that entry is also used for
        # unrelated bits (e.g. DF_1_PIE). The actual NOW bit must be set,
        # or the legacy boolean DT_BIND_NOW tag must be present.
        has_bind_now = binary.has(lief.ELF.DynamicEntry.TAG.BIND_NOW)
        if not has_bind_now and binary.has(lief.ELF.DynamicEntry.TAG.FLAGS):
            flags = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS)
            has_bind_now = flags.has(lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW)
        if not has_bind_now and binary.has(lief.ELF.DynamicEntry.TAG.FLAGS_1):
            flags1 = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
            has_bind_now = flags1.has(lief.ELF.DynamicEntryFlags.FLAG.NOW)
        if has_relro_segment and has_bind_now:
            report.relro = "full"
        elif has_relro_segment:
            report.relro = "partial"
        else:
            report.relro = "none"
    except Exception:
        report.notes.append("could not determine RELRO")

    try:
        symbol_names = {s.name for s in binary.dynamic_symbols}
        report.stack_canary = "__stack_chk_fail" in symbol_names
    except Exception:
        report.stack_canary = None

    try:
        report.stripped = binary.header.section_headers_offset == 0 or not any(
            s.name == ".symtab" for s in binary.sections
        )
    except Exception:
        pass

    return report


def _analyze_pe(binary: lief.PE.Binary) -> MitigationReport:
    report = MitigationReport(format="PE")
    try:
        characteristics = binary.optional_header.dll_characteristics_lists
        report.nx = lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT in characteristics
        report.pie_or_aslr = lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE in characteristics
        report.cfg = lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF in characteristics
        report.safe_seh = lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NO_SEH not in characteristics
    except Exception as exc:
        report.notes.append(f"could not read DLL characteristics: {exc}")

    try:
        report.signed = binary.has_signatures
    except Exception:
        report.signed = None

    try:
        report.stack_canary = any("__security_check_cookie" in f.name for f in binary.imported_functions)
    except Exception:
        pass

    return report


def _analyze_macho(binary: lief.MachO.Binary) -> MitigationReport:
    report = MitigationReport(format="Mach-O")
    try:
        report.pie_or_aslr = binary.header.has(lief.MachO.Header.FLAGS.PIE)
    except Exception:
        pass
    try:
        report.nx = binary.header.has(lief.MachO.Header.FLAGS.NO_HEAP_EXECUTION)
    except Exception:
        pass
    return report


def analyze(path: str) -> BinaryReport:
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"LIEF could not parse '{path}' as ELF/PE/Mach-O")

    if isinstance(binary, lief.ELF.Binary):
        mitigations = _analyze_elf(binary)
        arch = str(binary.header.machine_type)
    elif isinstance(binary, lief.PE.Binary):
        mitigations = _analyze_pe(binary)
        arch = str(binary.header.machine)
    elif isinstance(binary, lief.MachO.Binary):
        mitigations = _analyze_macho(binary)
        arch = str(binary.header.cpu_type)
    else:
        mitigations = MitigationReport(format="unknown")
        arch = None

    try:
        imports = sorted({f.name for f in binary.imported_functions})
    except Exception:
        imports = []
    try:
        exports = sorted({f.name for f in binary.exported_functions})
    except Exception:
        exports = []

    risky_lower = {r.lower() for r in RISKY_IMPORTS}
    risky = sorted(i for i in imports if i.lower().lstrip("_") in risky_lower)
    sections = [s.name for s in binary.sections] if hasattr(binary, "sections") else []

    return BinaryReport(
        path=path,
        format=mitigations.format,
        arch=arch,
        mitigations=mitigations,
        risky_imports=risky,
        imports=imports[:500],
        exports=exports[:500],
        sections=sections,
    )
