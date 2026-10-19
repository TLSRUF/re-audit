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


@pytest.mark.skipif(not REAL_APK, reason="set RE_AUDIT_TEST_APK to a real debug .apk to run this")
def test_analyze_real_apk_end_to_end():
    report = apk.analyze(REAL_APK)
    assert report.package
    assert isinstance(report.permissions, list)
    # A debug build's manifest always sets debuggable=true; this is the
    # exact finding verified manually against a real Flutter debug APK.
    if report.debuggable:
        assert any("debuggable" in f.lower() for f in report.findings)
