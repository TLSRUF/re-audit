"""Hardcoded secret / credential pattern detection.

Scans text (decoded strings from a binary, source file, or config) for
patterns that commonly indicate leaked secrets. This is heuristic and will
produce false positives -- it flags candidates for human review, it does
not confirm a secret is real or exploitable.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# (label, compiled regex)
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key (heuristic)", re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("Generic Bearer Token", re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_.=]{20,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Generic password assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"\s]{4,}['\"]")),
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][^'\"\s]{8,}['\"]")),
    ("Hardcoded DB connection string", re.compile(r"(?i)(mysql|postgres|postgresql|mongodb)://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
]


@dataclass
class SecretFinding:
    label: str
    match: str
    context: str
    offset: int
    entropy: float = 0.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(match: str) -> str:
    if len(match) <= 8:
        return "*" * len(match)
    return match[:4] + "..." + match[-4:]


def scan_text(text: str, context_window: int = 24) -> list[SecretFinding]:
    """Scan a text blob for secret-like patterns. Returns redacted findings."""
    findings: list[SecretFinding] = []
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            start = max(0, m.start() - context_window)
            end = min(len(text), m.end() + context_window)
            context = text[start:end]
            findings.append(
                SecretFinding(
                    label=label,
                    match=_redact(m.group(0)),
                    context=context.replace("\n", " "),
                    offset=m.start(),
                    entropy=round(_shannon_entropy(m.group(0)), 2),
                )
            )
    return findings


_HAS_DIGIT = re.compile(r"\d")
# Matches typical identifier casing like "WaitForSingleObjectEx" or
# "K32GetModuleFileNameExW": words that start with an uppercase letter
# followed by lowercase letters, chained together. Real secrets (base64,
# hex, API keys) essentially never look like this.
_CAMEL_CASE_IDENTIFIER = re.compile(r"^(?:[A-Z][a-z0-9]*|[0-9]+){2,}$")


def scan_high_entropy_tokens(text: str, min_len: int = 24, threshold: float = 4.3) -> list[SecretFinding]:
    """Flag long high-entropy tokens (base64/hex-looking blobs) that regex might miss.

    Requires at least one digit (real secrets are essentially never
    pure-alphabetic) and excludes CamelCase-identifier-shaped tokens, which
    cuts out the dominant false-positive source: long API/function names
    extracted from binaries (e.g. "WaitForSingleObjectEx").
    """
    findings: list[SecretFinding] = []
    for m in re.finditer(r"[A-Za-z0-9+/_=\-]{%d,}" % min_len, text):
        token = m.group(0)
        if not _HAS_DIGIT.search(token):
            continue
        if _CAMEL_CASE_IDENTIFIER.match(token):
            continue
        ent = _shannon_entropy(token)
        if ent >= threshold:
            start = max(0, m.start() - 16)
            end = min(len(text), m.end() + 16)
            findings.append(
                SecretFinding(
                    label="High-entropy token (possible secret)",
                    match=_redact(token),
                    context=text[start:end].replace("\n", " "),
                    offset=m.start(),
                    entropy=round(ent, 2),
                )
            )
    return findings
