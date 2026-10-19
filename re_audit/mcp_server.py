"""MCP server exposing re-audit's static analysis tools to AI agents.

Scope: static inspection of local files only (binaries, APKs). There is no
network tool here -- the server cannot be used to send traffic to a live
target. Only point it at files you own or are explicitly authorized to
test (your own builds, CTF binaries, in-scope bug-bounty assets).
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import report as report_mod
from .analyzers import apk as apk_analyzer
from .analyzers import binary as binary_analyzer
from .analyzers import secrets as secrets_analyzer
from .analyzers import strings_scan
from .detect import detect_type

mcp = FastMCP(
    "re-audit",
    instructions=(
        "Static reverse-engineering-assisted vulnerability triage tools. "
        "Use these ONLY on local files the user owns or is explicitly "
        "authorized to test (their own builds, CTF binaries, or an "
        "in-scope bug-bounty asset). All tools are read-only static "
        "analysis: they never execute the target and never make network "
        "requests. Before running a scan, confirm with the user that the "
        "file is in-scope. Findings are heuristic candidates for human "
        "review, not confirmed, exploitable vulnerabilities -- present "
        "them that way."
    ),
)


def _asdict(obj: Any) -> Any:
    return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else obj


def _resolve(path: str) -> str:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {p}")
    return str(p)


@mcp.tool()
def full_audit(path: str) -> dict:
    """Run the complete static audit on a file (auto-detects ELF/PE/Mach-O/APK).

    Combines string extraction, hardcoded-secret scanning, binary exploit
    mitigation checks, and (for APKs) manifest/permission analysis into one
    report with a `summary_findings` list. Only use on files the caller is
    authorized to test.
    """
    return report_mod.audit_file(_resolve(path))


@mcp.tool()
def detect_file_type(path: str) -> dict:
    """Identify whether a file is an ELF, PE, Mach-O binary, APK, JAR, or unknown, by magic bytes."""
    resolved = _resolve(path)
    return {"path": resolved, "detected_type": detect_type(resolved)}


@mcp.tool()
def scan_strings(path: str, sample_size: int = 40) -> dict:
    """Extract printable strings from a file and classify URLs, IPs, paths, and risky API names."""
    resolved = _resolve(path)
    with open(resolved, "rb") as f:
        data = f.read()
    return _asdict(strings_scan.analyze(data, sample_size=sample_size))


@mcp.tool()
def scan_secrets(path: str) -> dict:
    """Scan a file's extracted strings for hardcoded credential/token/key patterns and high-entropy blobs.

    Matches are redacted in the output. These are heuristic candidates --
    verify manually before treating any match as a confirmed live secret.
    """
    resolved = _resolve(path)
    with open(resolved, "rb") as f:
        data = f.read()
    text = "\n".join(strings_scan.extract_strings(data))
    return {
        "pattern_matches": [_asdict(f) for f in secrets_analyzer.scan_text(text)],
        "high_entropy_tokens": [_asdict(f) for f in secrets_analyzer.scan_high_entropy_tokens(text)[:50]],
    }


@mcp.tool()
def scan_binary_mitigations(path: str) -> dict:
    """Check an ELF/PE/Mach-O binary's exploit mitigations (NX, PIE/ASLR, RELRO, stack canary, CFG)
    and list imported functions historically associated with memory-corruption bugs.
    """
    return _asdict(binary_analyzer.analyze(_resolve(path)))


@mcp.tool()
def scan_apk(path: str) -> dict:
    """Static security audit of an Android APK: debuggable/backup/cleartext flags, dangerous
    permissions, and exported components (activities/services/receivers/providers) lacking guards.
    """
    return _asdict(apk_analyzer.analyze(_resolve(path)))


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
