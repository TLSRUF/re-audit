from re_audit.analyzers import binary

NOTEPAD = r"C:\Windows\System32\notepad.exe"


def test_analyzes_pe_binary():
    report = binary.analyze(NOTEPAD)
    assert report.format == "PE"
    assert report.mitigations.nx is True
    assert report.mitigations.pie_or_aslr is True


def test_risky_import_matching_is_exact_not_substring():
    # Regression test: a naive substring match of "gets" against import
    # names like "GetSaveFileNameW" / "GetStartupInfoW" produced false
    # positives. Exact (case-insensitive) matching must not flag these.
    report = binary.analyze(NOTEPAD)
    false_positive_prone = {"GetSaveFileNameW", "GetStartupInfoW", "GetSubMenu", "GetSystemMenu"}
    assert not (false_positive_prone & set(report.risky_imports))


def test_raises_on_non_binary_file(tmp_path):
    bogus = tmp_path / "not_a_binary.bin"
    bogus.write_bytes(b"this is plain text, not a PE/ELF/Mach-O file")
    try:
        binary.analyze(str(bogus))
        assert False, "expected ValueError for unparsable file"
    except ValueError:
        pass
