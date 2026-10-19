"""Extract printable strings from any file and flag interesting ones.

Pure-Python reimplementation of `strings` (so it works without the binutils
`strings` binary being installed) plus simple classification of URLs,
IPs, file paths, and suspicious API/function names.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MIN_LEN = 4

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
# UTF-16LE strings are common in Windows PE binaries (wide-char literals).
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)

URL_RE = re.compile(r"https?://[^\s'\"<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"<>]+")
UNIX_PATH_RE = re.compile(r"/(?:etc|home|usr|var|tmp|root)/[^\s'\"<>]+")

# Dangerous / commonly-misused function and API names worth flagging when
# seen as literal strings (import names, log strings, debug symbols left in).
RISKY_SYMBOLS = {
    "strcpy", "strcat", "sprintf", "gets", "system", "exec", "popen",
    "memcpy", "alloca", "vsprintf", "scanf", "ShellExecute", "WinExec",
    "CreateProcess", "LoadLibrary", "VirtualAlloc", "mprotect", "ptrace",
    "eval(", "pickle.loads", "yaml.load(", "subprocess.call", "os.system",
    "Runtime.exec", "ProcessBuilder", "md5", "sha1", "ECB", "DES",
}


@dataclass
class StringsReport:
    total_strings: int
    urls: list[str]
    ips: list[str]
    paths: list[str]
    risky_symbols: list[str]
    sample: list[str]


def extract_strings(data: bytes, min_len: int = MIN_LEN) -> list[str]:
    out: list[str] = []
    for m in _ASCII_RUN.finditer(data):
        out.append(m.group(0).decode("ascii", errors="ignore"))
    for m in _UTF16_RUN.finditer(data):
        try:
            out.append(m.group(0).decode("utf-16-le", errors="ignore"))
        except UnicodeDecodeError:
            continue
    return out


def analyze(data: bytes, sample_size: int = 40) -> StringsReport:
    strings = extract_strings(data)
    joined = "\n".join(strings)

    urls = sorted(set(URL_RE.findall(joined)))
    ips = sorted(set(IP_RE.findall(joined)))
    paths = sorted(set(WINDOWS_PATH_RE.findall(joined)) | set(UNIX_PATH_RE.findall(joined)))

    risky = sorted({sym for s in strings for sym in RISKY_SYMBOLS if sym in s})

    return StringsReport(
        total_strings=len(strings),
        urls=urls[:200],
        ips=ips[:200],
        paths=paths[:200],
        risky_symbols=risky,
        sample=strings[:sample_size],
    )
