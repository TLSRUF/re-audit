"""Lightweight file-type sniffing by magic bytes (no external deps)."""
from __future__ import annotations

import zipfile


def detect_type(path: str) -> str:
    with open(path, "rb") as f:
        header = f.read(8)

    if header[:2] == b"MZ":
        return "pe"
    if header[:4] == b"\x7fELF":
        return "elf"
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") or header[:4] == b"\xca\xfe\xba\xbe":
        return "macho"
    if header[:2] == b"PK":
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" in names and "classes.dex" in names:
                    return "apk"
                if any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names:
                    return "jar"
        except zipfile.BadZipFile:
            pass
        return "zip"
    return "unknown"
