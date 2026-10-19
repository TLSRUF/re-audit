from re_audit.analyzers import strings_scan


def test_extracts_ascii_strings():
    data = b"\x00\x00hello world\x00\x01\x02short\x00" + b"A" * 3
    strings = strings_scan.extract_strings(data)
    assert "hello world" in strings


def test_extracts_utf16le_strings():
    data = "wide string here".encode("utf-16-le")
    strings = strings_scan.extract_strings(data)
    assert any("wide string here" in s for s in strings)


def test_classifies_urls_and_ips():
    data = b"connect to http://example.com/api and 192.168.1.1 for config"
    report = strings_scan.analyze(data)
    assert "http://example.com/api" in report.urls
    assert "192.168.1.1" in report.ips


def test_flags_risky_symbols():
    data = b"call strcpy(dst, src) then system(cmd)"
    report = strings_scan.analyze(data)
    assert "strcpy" in report.risky_symbols
    assert "system" in report.risky_symbols


def test_does_not_flag_clean_text():
    data = b"nothing interesting here at all, just normal words"
    report = strings_scan.analyze(data)
    assert report.risky_symbols == []
    assert report.urls == []
