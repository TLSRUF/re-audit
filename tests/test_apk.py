import os
import zipfile

import pytest

from re_audit.analyzers import apk

# Point this at a real debug APK you own to exercise the full parser path.
# Not bundled in the repo (binary test fixtures bloat git history) -- set
# RE_AUDIT_TEST_APK locally to run this test; it's skipped otherwise.
REAL_APK = os.environ.get("RE_AUDIT_TEST_APK")


def test_analyze_raises_cleanly_on_garbage_input(tmp_path):
    """apk.analyze() must fail with a clear error on a non-APK file rather
    than crashing with an unrelated traceback -- this is the error path the
    MCP server and CLI both rely on to report a clean message instead of
    a stack trace."""
    path = tmp_path / "not_really.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"not valid binary AXML")
        zf.writestr("classes.dex", b"not a real dex file")
    with pytest.raises(Exception):
        apk.analyze(str(path))


# --- Zip-bomb regressions ------------------------------------------------
# A security-audit-skill review found that androguard/apkInspector decompress
# zip entries (e.g. AndroidManifest.xml) with no size cap, trusting the
# attacker-controlled "uncompressed size" header field: a sub-2MB crafted
# APK was confirmed to force ~1-2GB of memory allocation before parsing
# even starts. _reject_zip_bomb() closes this using zipfile's header-only
# central-directory read (no decompression) to check claimed sizes first.
# These tests monkeypatch the cap down so they stay fast and don't need to
# actually build multi-hundred-MB files.

def test_rejects_single_entry_claiming_more_than_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(apk, "MAX_APK_ENTRY_UNCOMPRESSED_BYTES", 1000)
    path = tmp_path / "bomb.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Highly compressible payload: tiny on disk, "huge" (over our
        # monkeypatched 1000-byte cap) once declared/decompressed.
        zf.writestr("AndroidManifest.xml", b"\x00" * 5000)
        zf.writestr("classes.dex", b"fake")
    with pytest.raises(ValueError, match="zip bomb"):
        apk.analyze(str(path))


def test_rejects_entries_summing_over_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(apk, "MAX_APK_ENTRY_UNCOMPRESSED_BYTES", 1000)
    path = tmp_path / "bomb2.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        # No single entry over the cap, but three together exceed it.
        zf.writestr("AndroidManifest.xml", b"\x00" * 400)
        zf.writestr("classes.dex", b"\x00" * 400)
        zf.writestr("resources.arsc", b"\x00" * 400)
    with pytest.raises(ValueError, match="zip bomb"):
        apk.analyze(str(path))


def test_does_not_reject_a_normal_small_apk_shape(tmp_path):
    # Sanity check: the zip-bomb guard must not false-positive on an
    # ordinary small file -- this should fail later, on invalid AXML
    # content (same as test_analyze_raises_cleanly_on_garbage_input), not
    # on the zip-bomb check itself.
    path = tmp_path / "normal.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"not valid binary AXML")
        zf.writestr("classes.dex", b"not a real dex file")
    with pytest.raises(Exception) as exc_info:
        apk.analyze(str(path))
    assert "zip bomb" not in str(exc_info.value)


@pytest.mark.skipif(not REAL_APK, reason="set RE_AUDIT_TEST_APK to a real debug .apk to run this")
def test_analyze_real_apk_end_to_end():
    report = apk.analyze(REAL_APK)
    assert report.package
    assert isinstance(report.permissions, list)
    # A debug build's manifest always sets debuggable=true; this is the
    # exact finding verified manually against a real Flutter debug APK.
    if report.debuggable:
        assert any("debuggable" in f.lower() for f in report.findings)
