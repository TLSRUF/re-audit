"""Resource-use guards for analyzing untrusted, potentially adversarial files.

re-audit's entire purpose is parsing attacker-controlled samples (CTF
binaries, real malware, hostile APKs). A security-audit-skill review of
this repo found concrete, cheaply-triggerable DoS vectors enabled by having
no size or time bound anywhere on that path: a sub-2MB crafted APK can
force ~1-2GB of memory via decompression-bomb amplification in a
dependency, and a crafted ~50-byte string can hang a regex scanner for
minutes (fixed at the regex level in analyzers/secrets.py, but a wall-clock
backstop here covers any future pattern with the same flaw). These guards
make both fail closed with a clear error instead of hanging or OOMing the
caller's process.
"""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Callable, TypeVar

MAX_FILE_SIZE_BYTES = 300 * 1024 * 1024  # 300 MB
DEFAULT_TIMEOUT_SECONDS = 30.0

T = TypeVar("T")


class FileTooLargeError(ValueError):
    pass


class AnalysisTimeoutError(RuntimeError):
    pass


def check_file_size(path: str, max_bytes: int = MAX_FILE_SIZE_BYTES) -> int:
    """Stat `path` and raise FileTooLargeError if it's over the cap. Returns
    the size. Cheap (one stat() call) even against a hostile file -- call
    this before any read/decompress/parse of the file's content.
    """
    size = Path(path).stat().st_size
    if size > max_bytes:
        raise FileTooLargeError(
            f"'{path}' is {size:,} bytes, over the {max_bytes:,}-byte limit. "
            "re-audit reads files fully into memory for analysis; very "
            "large (or crafted) files are rejected rather than risking a "
            "hang or out-of-memory condition."
        )
    return size


def read_file_bounded(path: str, max_bytes: int = MAX_FILE_SIZE_BYTES) -> bytes:
    """check_file_size() then read the whole file. Use instead of a bare
    open(path, 'rb').read() / Path.read_bytes() for any untrusted input."""
    check_file_size(path, max_bytes)
    return Path(path).read_bytes()


def run_with_timeout(
    func: Callable[..., T], *args, timeout: float = DEFAULT_TIMEOUT_SECONDS, **kwargs
) -> T:
    """Run func(*args, **kwargs) in a worker thread with a wall-clock
    deadline. Raises AnalysisTimeoutError if it doesn't finish in time.

    Windows has no SIGALRM, so a thread + future is the portable way to
    bound a call that might hang on pathological input (a stuck regex, or
    a native parser spinning on a malformed file). On timeout, the worker
    thread is NOT forcibly killed -- Python cannot safely do that,
    especially mid-call into native code (LIEF, androguard) -- so it keeps
    running in the background using CPU/memory until it finishes or the
    process exits. This still protects the CALLER from hanging forever,
    which is the property that matters for a CLI command or one MCP tool
    call: control returns to the caller, which can report a clear timeout
    error instead of appearing frozen.
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func, *args, **kwargs)
    try:
        result = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False)
        name = getattr(func, "__name__", repr(func))
        raise AnalysisTimeoutError(
            f"{name} did not finish within {timeout}s -- aborting as a "
            "wall-clock guard against pathological or adversarial input."
        ) from None
    else:
        executor.shutdown(wait=False)
        return result
