import time

import pytest

from re_audit.limits import (
    AnalysisTimeoutError,
    FileTooLargeError,
    check_file_size,
    read_file_bounded,
    run_with_timeout,
)


def test_check_file_size_passes_under_cap(tmp_path):
    path = tmp_path / "small.bin"
    path.write_bytes(b"x" * 100)
    assert check_file_size(str(path), max_bytes=1000) == 100


def test_check_file_size_rejects_over_cap(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 1000)
    with pytest.raises(FileTooLargeError):
        check_file_size(str(path), max_bytes=500)


def test_read_file_bounded_returns_content_under_cap(tmp_path):
    path = tmp_path / "ok.bin"
    path.write_bytes(b"hello")
    assert read_file_bounded(str(path), max_bytes=1000) == b"hello"


def test_read_file_bounded_rejects_over_cap_without_reading(tmp_path):
    path = tmp_path / "ok.bin"
    path.write_bytes(b"hello world")
    with pytest.raises(FileTooLargeError):
        read_file_bounded(str(path), max_bytes=5)


def test_run_with_timeout_returns_fast_result():
    assert run_with_timeout(lambda: 42, timeout=5) == 42


def test_run_with_timeout_raises_on_slow_call():
    def slow():
        time.sleep(5)
        return "done"

    t0 = time.perf_counter()
    with pytest.raises(AnalysisTimeoutError):
        run_with_timeout(slow, timeout=0.2)
    elapsed = time.perf_counter() - t0
    # Must return control promptly -- this is the whole point of the
    # guard. If shutdown() ever blocks waiting for the stuck thread, this
    # would take ~5s instead of ~0.2s.
    assert elapsed < 1.0


def test_run_with_timeout_propagates_the_function_s_own_exception():
    def boom():
        raise ValueError("real error")

    with pytest.raises(ValueError, match="real error"):
        run_with_timeout(boom, timeout=5)
