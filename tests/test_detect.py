import zipfile

from re_audit.detect import detect_type


def test_detects_pe_from_system_binary():
    assert detect_type(r"C:\Windows\System32\notepad.exe") == "pe"


def test_detects_apk_by_required_zip_entries(tmp_path):
    path = tmp_path / "sample.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"fake")
        zf.writestr("classes.dex", b"fake")
    assert detect_type(str(path)) == "apk"


def test_detects_jar_by_manifest(tmp_path):
    path = tmp_path / "sample.jar"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0")
    assert detect_type(str(path)) == "jar"


def test_plain_zip_without_markers(tmp_path):
    path = tmp_path / "plain.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    assert detect_type(str(path)) == "zip"


def test_unknown_for_arbitrary_bytes(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"not a recognized file format at all")
    assert detect_type(str(path)) == "unknown"
