"""Combine per-analyzer results into one JSON-serializable audit report."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from .analyzers import binary as binary_analyzer
from .analyzers import secrets as secrets_analyzer
from .analyzers import strings_scan
from .detect import detect_type

SCOPE_DISCLAIMER = (
    "This report is for static analysis of files you own or are explicitly "
    "authorized to test (your own builds, CTF targets, or an in-scope bug "
    "bounty asset). It performs no network requests and does not execute "
    "the target. Findings are heuristic candidates for manual review, not "
    "confirmed vulnerabilities."
)


def _asdict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return obj


def audit_file(path: str, max_strings_sample: int = 40) -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {path}")

    file_type = detect_type(str(p))
    data = p.read_bytes()

    report: dict[str, Any] = {
        "scope_disclaimer": SCOPE_DISCLAIMER,
        "path": str(p),
        "size_bytes": len(data),
        "detected_type": file_type,
        "sections": {},
        "summary_findings": [],
    }

    # Strings + secret scanning applies to every file type.
    strings_report = strings_scan.analyze(data, sample_size=max_strings_sample)
    report["sections"]["strings"] = _asdict(strings_report)

    joined_text = "\n".join(strings_report.sample) if max_strings_sample >= strings_report.total_strings else "\n".join(strings_scan.extract_strings(data))
    secret_findings = secrets_analyzer.scan_text(joined_text)
    high_entropy = secrets_analyzer.scan_high_entropy_tokens(joined_text)
    report["sections"]["secrets"] = {
        "pattern_matches": [_asdict(f) for f in secret_findings],
        "high_entropy_tokens": [_asdict(f) for f in high_entropy[:50]],
    }
    if secret_findings:
        report["summary_findings"].append(
            f"HIGH: {len(secret_findings)} potential hardcoded secret(s) detected (see sections.secrets)."
        )
    if strings_report.risky_symbols:
        report["summary_findings"].append(
            f"MEDIUM: references to risky functions/APIs found: {', '.join(strings_report.risky_symbols)}"
        )

    if file_type in ("elf", "pe", "macho"):
        try:
            bin_report = binary_analyzer.analyze(str(p))
            report["sections"]["binary"] = _asdict(bin_report)
            m = bin_report.mitigations
            if m.nx is False:
                report["summary_findings"].append("HIGH: NX/DEP disabled -- stack/heap pages are executable.")
            if m.pie_or_aslr is False:
                report["summary_findings"].append("MEDIUM: no PIE/ASLR base randomization -- easier memory-corruption exploitation.")
            if m.relro == "none":
                report["summary_findings"].append("MEDIUM: no RELRO -- GOT is writable, aiding GOT-overwrite exploits.")
            if m.stack_canary is False:
                report["summary_findings"].append("MEDIUM: no stack canary detected.")
            if bin_report.risky_imports:
                report["summary_findings"].append(
                    f"MEDIUM: imports known memory-unsafe functions: {', '.join(bin_report.risky_imports)}"
                )
        except Exception as exc:
            report["sections"]["binary_error"] = str(exc)

    elif file_type == "apk":
        from .analyzers import apk as apk_analyzer
        try:
            apk_report = apk_analyzer.analyze(str(p))
            report["sections"]["apk"] = _asdict(apk_report)
            report["summary_findings"].extend(apk_report.findings)
        except Exception as exc:
            report["sections"]["apk_error"] = str(exc)

    return report


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)
